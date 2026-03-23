package output

import (
	"strings"

	"snablr/internal/browsercredinspect"
	"snablr/internal/scanner"
)

const browserCredCorrelationRuleID = "correlation.browser.profile_credential_store"

func buildBrowserCredentialStoreCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host    string
		share   string
		profile string
	}

	type profileBucket struct {
		firefoxLogins []scanner.Finding
		firefoxKey4   []scanner.Finding
		chromeLogin   []scanner.Finding
		chromeCookies []scanner.Finding
	}

	grouped := make(map[bucketKey]*profileBucket)
	for _, finding := range findings {
		family := browserCredentialStoreFamily(finding)
		if family == "" {
			continue
		}
		profile := browsercredinspect.ProfileContext(finding.FilePath)
		if profile == "" {
			continue
		}
		key := bucketKey{
			host:    strings.ToLower(strings.TrimSpace(finding.Host)),
			share:   strings.ToLower(strings.TrimSpace(finding.Share)),
			profile: profile,
		}
		bucket := grouped[key]
		if bucket == nil {
			bucket = &profileBucket{}
			grouped[key] = bucket
		}
		switch family {
		case "firefox-logins":
			bucket.firefoxLogins = append(bucket.firefoxLogins, finding)
		case "firefox-key4":
			bucket.firefoxKey4 = append(bucket.firefoxKey4, finding)
		case "chromium-login-data":
			bucket.chromeLogin = append(bucket.chromeLogin, finding)
		case "chromium-cookies":
			bucket.chromeCookies = append(bucket.chromeCookies, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		switch {
		case len(bucket.firefoxLogins) > 0 && len(bucket.firefoxKey4) > 0:
			out = append(out, newBrowserCredentialStoreCorrelatedFinding(
				selectBestCorrelationAnchor(bucket.firefoxLogins),
				selectBestCorrelationAnchor(bucket.firefoxKey4),
				"Firefox logins.json + key4.db",
				"critical",
				84,
			))
		case len(bucket.chromeLogin) > 0 && len(bucket.chromeCookies) > 0:
			out = append(out, newBrowserCredentialStoreCorrelatedFinding(
				selectBestCorrelationAnchor(bucket.chromeLogin),
				selectBestCorrelationAnchor(bucket.chromeCookies),
				"Chromium Login Data + Cookies",
				"high",
				78,
			))
		}
	}
	return out
}

func browserCredentialStoreFamily(f scanner.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "browsercredinspect.firefox.logins":
		return "firefox-logins"
	case "browsercredinspect.firefox.key4":
		return "firefox-key4"
	case "browsercredinspect.chromium.login_data":
		return "chromium-login-data"
	case "browsercredinspect.chromium.cookies":
		return "chromium-cookies"
	default:
		return ""
	}
}

func newBrowserCredentialStoreCorrelatedFinding(primary, support scanner.Finding, match, severity string, score int) scanner.Finding {
	ruleIDs := append([]string{}, primary.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, support.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, browserCredCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"multiple exact browser credential-store artifacts were found under the same browser profile context",
		"paired browser profile artifacts increase the chance that offline credential or session extraction is possible from the exposed profile data",
	})
	signals := []scanner.SupportingSignal{
		{
			SignalType: primary.SignalType,
			RuleID:     primary.RuleID,
			RuleName:   primary.RuleName,
			Match:      primary.Match,
			Confidence: primary.Confidence,
			Weight:     18,
			Reason:     "exact browser credential-store artifact was identified",
		},
		{
			SignalType: support.SignalType,
			RuleID:     support.RuleID,
			RuleName:   support.RuleName,
			Match:      support.Match,
			Confidence: support.Confidence,
			Weight:     18,
			Reason:     "a second exact browser profile credential-store artifact was identified",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "paired browser credential-store artifacts were found under the same normalized browser profile context",
		},
		{
			SignalType: "correlation",
			RuleID:     browserCredCorrelationRuleID,
			RuleName:   "Browser Credential Store Exposure Path",
			Match:      match,
			Confidence: "high",
			Weight:     34,
			Reason:     "paired browser profile artifacts strongly increase the chance of usable offline credential or session extraction exposure",
		},
	}

	tags := uniqueStrings(append(append(append([]string{}, primary.Tags...), support.Tags...), []string{
		"correlation:browser-credential-store",
		"artifact:browser-credstore",
	}...))
	context := "Paired browser profile context:\n" + primary.FilePath + "\n" + support.FilePath
	return scanner.Finding{
		RuleID:            browserCredCorrelationRuleID,
		RuleName:          "Browser Credential Store Exposure Path",
		Severity:          severity,
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   score,
		ConfidenceReasons: reasons,
		Category:          "browser-credentials",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   score,
			FinalScore:                  score,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 36,
			ValueQualityScore:           0,
			ValueQualityLabel:           "medium",
			ValueQualityReason:          "confidence comes from exact browser credential-store artifact identity and profile-level correlation rather than extracted secrets",
			CorrelationContribution:     34,
			PathContextContribution:     12,
		},
		Priority:            maxInt(primary.Priority, support.Priority),
		PriorityReason:      firstNonEmpty(primary.PriorityReason, support.PriorityReason),
		SharePriority:       maxInt(primary.SharePriority, support.SharePriority),
		SharePriorityReason: firstNonEmpty(primary.SharePriorityReason, support.SharePriorityReason),
		FilePath:            primary.FilePath,
		Share:               primary.Share,
		ShareDescription:    primary.ShareDescription,
		ShareType:           primary.ShareType,
		Host:                primary.Host,
		Source:              firstNonEmpty(primary.Source, support.Source),
		ArchivePath:         firstNonEmpty(primary.ArchivePath, support.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(primary.ArchiveMemberPath, support.ArchiveMemberPath),
		ArchiveLocalInspect: primary.ArchiveLocalInspect || support.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(primary.DFSNamespacePath, support.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(primary.DFSLinkPath, support.DFSLinkPath),
		SignalType:          "correlation",
		Match:               match,
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             match,
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified multiple exact browser credential-store artifacts in the same normalized browser profile context.",
		RuleExplanation:     "This finding is promoted only when exact paired browser credential-store artifacts co-occur within the same normalized browser profile.",
		RuleRemediation:     "Restrict access to browser profile data, remove unnecessary copied profiles from shared storage, and review whether exposed browser credential-store artifacts could support offline credential or session extraction.",
		FromSYSVOL:          primary.FromSYSVOL || support.FromSYSVOL,
		FromNETLOGON:        primary.FromNETLOGON || support.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "path", "validated"},
		SupportingSignals:   signals,
		Tags:                tags,
	}
}

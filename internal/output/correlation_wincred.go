package output

import (
	"strings"

	"snablr/internal/scanner"
	"snablr/internal/wincredinspect"
)

const windowsCredCorrelationRuleID = "correlation.windows.dpapi_credential_store"

func buildWindowsCredentialStoreCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host    string
		share   string
		profile string
	}

	type profileBucket struct {
		credentials []scanner.Finding
		vault       []scanner.Finding
		protect     []scanner.Finding
	}

	grouped := make(map[bucketKey]*profileBucket)
	for _, finding := range findings {
		family := windowsCredentialStoreFamily(finding)
		if family == "" {
			continue
		}
		profile := wincredinspect.ProfileContext(finding.FilePath)
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
		case "credentials":
			bucket.credentials = append(bucket.credentials, finding)
		case "vault":
			bucket.vault = append(bucket.vault, finding)
		case "protect":
			bucket.protect = append(bucket.protect, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		if len(bucket.protect) == 0 {
			continue
		}
		var support scanner.Finding
		supportMatch := ""
		if len(bucket.credentials) > 0 && len(bucket.vault) > 0 {
			support = selectBestCorrelationAnchor(append(append([]scanner.Finding{}, bucket.credentials...), bucket.vault...))
			supportMatch = "Protect + Credentials + Vault"
		} else if len(bucket.credentials) > 0 {
			support = selectBestCorrelationAnchor(bucket.credentials)
			supportMatch = "Protect + Credentials"
		} else if len(bucket.vault) > 0 {
			support = selectBestCorrelationAnchor(bucket.vault)
			supportMatch = "Protect + Vault"
		} else {
			continue
		}
		out = append(out, newWindowsCredentialStoreCorrelatedFinding(selectBestCorrelationAnchor(bucket.protect), support, supportMatch))
	}
	return out
}

func windowsCredentialStoreFamily(f scanner.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "wincredinspect.path.credentials":
		return "credentials"
	case "wincredinspect.path.vault":
		return "vault"
	case "wincredinspect.path.protect":
		return "protect"
	default:
		return ""
	}
}

func newWindowsCredentialStoreCorrelatedFinding(protect, support scanner.Finding, match string) scanner.Finding {
	ruleIDs := append([]string{}, protect.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, support.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, windowsCredCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"multiple Windows credential-store path families were found under the same profile context",
		"DPAPI Protect material co-occurred with Windows Credentials or Vault paths in the same profile context",
	})

	signals := []scanner.SupportingSignal{
		{
			SignalType: protect.SignalType,
			RuleID:     protect.RuleID,
			RuleName:   protect.RuleName,
			Match:      protect.Match,
			Confidence: protect.Confidence,
			Weight:     18,
			Reason:     "Windows DPAPI Protect path was identified",
		},
		{
			SignalType: support.SignalType,
			RuleID:     support.RuleID,
			RuleName:   support.RuleName,
			Match:      support.Match,
			Confidence: support.Confidence,
			Weight:     18,
			Reason:     "Windows Credentials or Vault path was identified",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "related DPAPI credential-store paths were found under the same normalized profile context",
		},
		{
			SignalType: "correlation",
			RuleID:     windowsCredCorrelationRuleID,
			RuleName:   "Windows DPAPI Credential Store Exposure Path",
			Match:      match,
			Confidence: "high",
			Weight:     34,
			Reason:     "paired DPAPI Protect and Windows credential-store paths strongly indicate reusable credential-store exposure",
		},
	}

	tags := uniqueStrings(append(append(append([]string{}, protect.Tags...), support.Tags...), []string{
		"correlation:windows-credential-store",
		"artifact:windows-credstore",
		"dpapi",
	}...))
	context := "Paired profile context:\n" + protect.FilePath + "\n" + support.FilePath
	score := 84
	if strings.EqualFold(strings.TrimSpace(match), "Protect + Credentials + Vault") {
		score = 88
	}

	return scanner.Finding{
		RuleID:            windowsCredCorrelationRuleID,
		RuleName:          "Windows DPAPI Credential Store Exposure Path",
		Severity:          "critical",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   score,
		ConfidenceReasons: reasons,
		Category:          "windows-credentials",
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
			ValueQualityReason:          "confidence comes from exact Windows credential-store path identity and profile-level DPAPI correlation",
			CorrelationContribution:     34,
			PathContextContribution:     12,
		},
		Priority:            maxInt(protect.Priority, support.Priority),
		PriorityReason:      firstNonEmpty(protect.PriorityReason, support.PriorityReason),
		SharePriority:       maxInt(protect.SharePriority, support.SharePriority),
		SharePriorityReason: firstNonEmpty(protect.SharePriorityReason, support.SharePriorityReason),
		FilePath:            protect.FilePath,
		Share:               protect.Share,
		ShareDescription:    protect.ShareDescription,
		ShareType:           protect.ShareType,
		Host:                protect.Host,
		Source:              firstNonEmpty(protect.Source, support.Source),
		ArchivePath:         firstNonEmpty(protect.ArchivePath, support.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(protect.ArchiveMemberPath, support.ArchiveMemberPath),
		ArchiveLocalInspect: protect.ArchiveLocalInspect || support.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(protect.DFSNamespacePath, support.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(protect.DFSLinkPath, support.DFSLinkPath),
		SignalType:          "correlation",
		Match:               match,
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             match,
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified DPAPI Protect material together with Windows Credentials or Vault paths in the same profile context.",
		RuleExplanation:     "This finding is promoted only when exact Windows credential-store path families co-occur within the same normalized user or profile context.",
		RuleRemediation:     "Restrict access immediately, remove unnecessary profile credential-store copies from shared storage, and review whether the exposed DPAPI-related material could enable credential recovery workflows.",
		FromSYSVOL:          protect.FromSYSVOL || support.FromSYSVOL,
		FromNETLOGON:        protect.FromNETLOGON || support.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "path", "validated"},
		SupportingSignals:   signals,
		Tags:                tags,
	}
}

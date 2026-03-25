package output

import (
	"strings"

	"snablr/internal/awsinspect"
	"snablr/internal/scanner"
)

const awsProfileCorrelationRuleID = "correlation.cloud.aws_profile_bundle"

func buildAWSCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host    string
		share   string
		profile string
	}

	type profileBucket struct {
		credentials []scanner.Finding
		config      []scanner.Finding
	}

	grouped := make(map[bucketKey]*profileBucket)
	for _, finding := range findings {
		family := awsArtifactFamily(finding)
		if family == "" {
			continue
		}
		profile := awsinspect.ProfileContext(finding.FilePath)
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
		case "config":
			bucket.config = append(bucket.config, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		if len(bucket.credentials) == 0 || len(bucket.config) == 0 {
			continue
		}
		out = append(out, newAWSCorrelatedFinding(
			selectBestCorrelationAnchor(bucket.credentials),
			selectBestCorrelationAnchor(bucket.config),
		))
	}
	return out
}

func awsArtifactFamily(f scanner.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "awsinspect.path.credentials", "awsinspect.content.credentials_bundle":
		return "credentials"
	case "awsinspect.path.config":
		return "config"
	default:
		return ""
	}
}

func newAWSCorrelatedFinding(credentials, config scanner.Finding) scanner.Finding {
	ruleIDs := append([]string{}, credentials.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, config.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, awsProfileCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"AWS shared credentials and AWS shared config were found together under the same normalized profile context",
		"paired AWS profile artifacts increase the chance that reusable CLI or API access is exposed",
	})

	signals := []scanner.SupportingSignal{
		{
			SignalType: credentials.SignalType,
			RuleID:     credentials.RuleID,
			RuleName:   credentials.RuleName,
			Match:      credentials.Match,
			Confidence: credentials.Confidence,
			Weight:     20,
			Reason:     "AWS shared credentials artifact or validated credential bundle was identified",
		},
		{
			SignalType: config.SignalType,
			RuleID:     config.RuleID,
			RuleName:   config.RuleName,
			Match:      config.Match,
			Confidence: config.Confidence,
			Weight:     14,
			Reason:     "AWS shared config artifact was identified under the same profile context",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "AWS credentials and config were found under the same normalized .aws profile path",
		},
		{
			SignalType: "correlation",
			RuleID:     awsProfileCorrelationRuleID,
			RuleName:   "AWS Credential Profile Bundle",
			Match:      ".aws/credentials + .aws/config",
			Confidence: "high",
			Weight:     28,
			Reason:     "paired AWS shared profile artifacts strongly indicate likely reusable CLI or API access material",
		},
	}

	context := "Paired AWS profile artifacts:\n" + credentials.FilePath + "\n" + config.FilePath
	tags := uniqueStrings(append(append([]string{}, credentials.Tags...), config.Tags...))
	tags = append(tags, "correlation:aws-profile-bundle", "artifact:aws-credentials", "artifact:aws-config")

	score := 78
	if strings.EqualFold(strings.TrimSpace(credentials.RuleID), "awsinspect.content.credentials_bundle") {
		score = 84
	}

	return scanner.Finding{
		RuleID:            awsProfileCorrelationRuleID,
		RuleName:          "AWS Credential Profile Bundle",
		Severity:          "high",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   score,
		ConfidenceReasons: reasons,
		Category:          "cloud",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   score,
			FinalScore:                  score,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 34,
			ValueQualityScore:           0,
			ValueQualityLabel:           "medium",
			ValueQualityReason:          "confidence comes from exact AWS artifact identity and same-profile correlation",
			CorrelationContribution:     28,
			PathContextContribution:     12,
		},
		Priority:            maxInt(credentials.Priority, config.Priority),
		PriorityReason:      firstNonEmpty(credentials.PriorityReason, config.PriorityReason),
		SharePriority:       maxInt(credentials.SharePriority, config.SharePriority),
		SharePriorityReason: firstNonEmpty(credentials.SharePriorityReason, config.SharePriorityReason),
		FilePath:            credentials.FilePath,
		Share:               credentials.Share,
		ShareDescription:    credentials.ShareDescription,
		ShareType:           credentials.ShareType,
		Host:                credentials.Host,
		Source:              firstNonEmpty(credentials.Source, config.Source),
		ArchivePath:         firstNonEmpty(credentials.ArchivePath, config.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(credentials.ArchiveMemberPath, config.ArchiveMemberPath),
		ArchiveLocalInspect: credentials.ArchiveLocalInspect || config.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(credentials.DFSNamespacePath, config.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(credentials.DFSLinkPath, config.DFSLinkPath),
		SignalType:          "correlation",
		Match:               ".aws/credentials + .aws/config",
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             "AWS shared credentials and config in same profile context",
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified AWS credentials and AWS config together in the same normalized profile context.",
		RuleExplanation:     "This finding is promoted only when exact AWS shared credentials and shared config artifacts co-occur in the same normalized .aws profile path.",
		RuleRemediation:     "Restrict access, remove copied AWS profile material from shared storage, and rotate exposed AWS credentials if the profile contains live keys.",
		FromSYSVOL:          credentials.FromSYSVOL || config.FromSYSVOL,
		FromNETLOGON:        credentials.FromNETLOGON || config.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "validated", "path"},
		SupportingSignals:   signals,
		Tags:                uniqueStrings(tags),
	}
}

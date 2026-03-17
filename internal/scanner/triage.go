package scanner

import "strings"

const (
	triageActionable = "actionable"
	triageConfigOnly = "config-only"
	triageWeakReview = "weak-review"
)

func applyTriageMetadata(f Finding) Finding {
	f.Correlated = len(f.MatchedSignalTypes) > 1 || len(f.MatchedRuleIDs) > 1
	f.TriageClass = triageClassForFinding(f)
	f.Actionable = f.TriageClass == triageActionable

	switch f.TriageClass {
	case triageConfigOnly:
		if severityRank(f.Severity) > severityRank("low") {
			f.Severity = "low"
		}
		if f.ConfidenceScore > 24 {
			f.ConfidenceScore = 24
		}
		f.Confidence = "low"
		f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "configuration artifact was identified without actionable evidence")
	case triageWeakReview:
		if severityRank(f.Severity) > severityRank("medium") {
			f.Severity = "medium"
		}
		if f.ConfidenceScore > 34 {
			f.ConfidenceScore = 34
		}
		if strings.TrimSpace(f.Confidence) == "" || confidenceRank(f.Confidence) > confidenceRank("medium") {
			f.Confidence = "medium"
		}
		f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "heuristic review signal did not include actionable evidence")
	default:
		if strings.TrimSpace(f.Confidence) == "" && f.ConfidenceScore > 0 {
			f.Confidence = confidenceLevelForScore(f.ConfidenceScore)
		}
	}

	return f
}

func triageClassForFinding(f Finding) string {
	if isConfigOnlyFinding(f) {
		return triageConfigOnly
	}
	if isWeakReviewFinding(f) {
		return triageWeakReview
	}
	return triageActionable
}

func isConfigOnlyFinding(f Finding) bool {
	if !strings.EqualFold(strings.TrimSpace(f.Category), "configuration") {
		return false
	}
	return !hasStrongEvidence(f)
}

func isWeakReviewFinding(f Finding) bool {
	if hasStrongEvidence(f) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f.Category)) {
	case "infrastructure", "scripts":
		return true
	default:
		return false
	}
}

func hasStrongEvidence(f Finding) bool {
	switch strings.ToLower(strings.TrimSpace(findingPrimarySignal(f))) {
	case "content", "validated":
		return true
	}

	category := strings.ToLower(strings.TrimSpace(f.Category))
	switch category {
	case "credentials", "crypto", "active-directory", "deployment", "password-manager", "database-access", "database-infrastructure", "database-artifacts":
		return true
	default:
		return false
	}
}

func findingPrimarySignal(f Finding) string {
	if strings.TrimSpace(f.SignalType) != "" {
		return strings.TrimSpace(f.SignalType)
	}
	if len(f.MatchedSignalTypes) > 0 {
		return strings.TrimSpace(f.MatchedSignalTypes[0])
	}
	return ""
}

func appendUniqueReason(values []string, reason string) []string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), reason) {
			return values
		}
	}
	return append(values, reason)
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

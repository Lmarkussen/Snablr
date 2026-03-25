package output

import "snablr/internal/scanner"

type liveFindingVisibility string

const (
	liveVisibilityPrimary    liveFindingVisibility = "primary"
	liveVisibilitySupporting liveFindingVisibility = "supporting"
)

func classifyLiveFindingVisibility(f scanner.Finding) liveFindingVisibility {
	if isPrimaryLiveFinding(f) {
		return liveVisibilityPrimary
	}
	return liveVisibilitySupporting
}

func isPrimaryLiveFinding(f scanner.Finding) bool {
	if !f.Actionable {
		return false
	}
	if isSupportingOnlyLiveRule(f.RuleID) {
		return false
	}
	return true
}

func filterPrimaryLiveFindings(findings []scanner.Finding) []scanner.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]scanner.Finding, 0, len(findings))
	for _, finding := range findings {
		if classifyLiveFindingVisibility(finding) != liveVisibilityPrimary {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func isSupportingOnlyLiveRule(ruleID string) bool {
	switch ruleID {
	case "filename.ssh_supporting_artifacts",
		"extension.database_and_backup_extensions":
		return true
	default:
		return false
	}
}

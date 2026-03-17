package output

import (
	"strings"

	"snablr/internal/scanner"
	"snablr/internal/seed"
)

type ValidationAware interface {
	SetValidationManifest(string)
}

type validationSummary struct {
	ExpectedItems        int                      `json:"expected_items"`
	FoundItems           int                      `json:"found_items"`
	MissedItems          int                      `json:"missed_items"`
	UnexpectedFindings   int                      `json:"unexpected_findings"`
	SuppressedConfigOnly int                      `json:"suppressed_config_only"`
	PromotedActionable   int                      `json:"promoted_actionable"`
	PromotedCorrelated   int                      `json:"promoted_correlated"`
	ClassCoverage        []validationClassSummary `json:"class_coverage,omitempty"`
	MissedExpected       []validationItem         `json:"missed_expected,omitempty"`
	OverPromoted         []validationItem         `json:"over_promoted,omitempty"`
	HasValidation        bool                     `json:"has_validation"`
}

type validationClassSummary struct {
	ExpectedClass string `json:"expected_class"`
	Label         string `json:"label"`
	Planted       int    `json:"planted"`
	Detected      int    `json:"detected"`
	Missed        int    `json:"missed"`
	Matched       int    `json:"matched"`
	Suppressed    int    `json:"suppressed"`
	Downgraded    int    `json:"downgraded"`
	Promoted      int    `json:"promoted"`
	Mismatched    int    `json:"mismatched"`
}

type validationItem struct {
	ExpectedClass       string `json:"expected_class,omitempty"`
	Label               string `json:"label,omitempty"`
	Category            string `json:"category,omitempty"`
	Host                string `json:"host,omitempty"`
	Share               string `json:"share,omitempty"`
	Path                string `json:"path,omitempty"`
	ObservedTriageClass string `json:"observed_triage_class,omitempty"`
	ObservedConfidence  string `json:"observed_confidence,omitempty"`
	ObservedCorrelated  bool   `json:"observed_correlated,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

func SetValidationManifest(sink scanner.FindingSink, manifestPath string) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(ValidationAware); ok {
		aware.SetValidationManifest(manifestPath)
	}
}

func buildValidationSummary(manifestPath string, findings []scanner.Finding) (*validationSummary, error) {
	if strings.TrimSpace(manifestPath) == "" {
		return nil, nil
	}
	report, err := seed.VerifyFindings(manifestPath, findings)
	if err != nil {
		return nil, err
	}

	summary := &validationSummary{
		ExpectedItems:        report.ExpectedItems,
		FoundItems:           report.FoundItems,
		MissedItems:          report.MissedItems,
		UnexpectedFindings:   report.UnexpectedFindings,
		SuppressedConfigOnly: len(report.SuppressedConfigOnly),
		PromotedActionable:   len(report.PromotedActionable),
		PromotedCorrelated:   len(report.PromotedCorrelated),
		HasValidation:        true,
	}

	if len(report.ClassCoverage) > 0 {
		summary.ClassCoverage = make([]validationClassSummary, 0, len(report.ClassCoverage))
		for _, item := range report.ClassCoverage {
			summary.ClassCoverage = append(summary.ClassCoverage, validationClassSummary{
				ExpectedClass: item.ExpectedClass,
				Label:         expectedClassLabel(item.ExpectedClass),
				Planted:       item.Planted,
				Detected:      item.Detected,
				Missed:        item.Missed,
				Matched:       item.Matched,
				Suppressed:    item.Suppressed,
				Downgraded:    item.Downgraded,
				Promoted:      item.Promoted,
				Mismatched:    item.Mismatched,
			})
		}
	}

	if len(report.Missed) > 0 {
		summary.MissedExpected = make([]validationItem, 0, len(report.Missed))
		for _, item := range report.Missed {
			summary.MissedExpected = append(summary.MissedExpected, validationItem{
				ExpectedClass: item.ExpectedClass,
				Label:         expectedClassLabel(item.ExpectedClass),
				Category:      item.Category,
				Host:          item.Host,
				Share:         item.Share,
				Path:          item.Path,
				Reason:        "seeded artifact did not surface in the scan results",
			})
		}
	}

	overPromoted := make([]validationItem, 0)
	for _, item := range report.ClassMismatches {
		if !isOverPromotedMismatch(item) {
			continue
		}
		overPromoted = append(overPromoted, validationItem{
			ExpectedClass:       item.Entry.ExpectedClass,
			Label:               expectedClassLabel(item.Entry.ExpectedClass),
			Category:            item.Entry.Category,
			Host:                item.Entry.Host,
			Share:               item.Entry.Share,
			Path:                item.Entry.Path,
			ObservedTriageClass: item.ObservedTriageClass,
			ObservedConfidence:  item.ObservedConfidence,
			ObservedCorrelated:  item.ObservedCorrelated,
			Reason:              item.Reason,
		})
	}
	summary.OverPromoted = overPromoted

	return summary, nil
}

func expectedClassLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "config-only":
		return "informational"
	case "weak-review":
		return "weak"
	case "actionable":
		return "actionable"
	case "correlated-high-confidence":
		return "correlated / high-confidence"
	default:
		return valueOrDash(value)
	}
}

func isOverPromotedMismatch(item seed.ClassVerificationItem) bool {
	expected := strings.ToLower(strings.TrimSpace(item.Entry.ExpectedClass))
	observed := strings.ToLower(strings.TrimSpace(item.ObservedTriageClass))
	if expected == "" || observed == "" {
		return false
	}

	switch expected {
	case "config-only":
		return observed == "actionable" || strings.EqualFold(item.ObservedConfidence, "high") || item.ObservedCorrelated
	case "weak-review":
		return observed == "actionable" || strings.EqualFold(item.ObservedConfidence, "high") || item.ObservedCorrelated
	default:
		return false
	}
}

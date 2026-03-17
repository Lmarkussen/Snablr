package output

import (
	"sync"

	"snablr/internal/scanner"
)

type ValidationModeAware interface {
	SetValidationMode(bool)
}

type validationModeSummary struct {
	Enabled                 bool    `json:"enabled"`
	TotalFindings           int     `json:"total_findings"`
	SuppressedFindings      int     `json:"suppressed_findings"`
	VisibleFindings         int     `json:"visible_findings"`
	DowngradedFindings      int     `json:"downgraded_findings"`
	FalsePositiveCandidates int     `json:"false_positive_candidates"`
	HighConfidenceFindings  int     `json:"high_confidence_findings"`
	HighConfidenceRatio     float64 `json:"high_confidence_ratio"`
	SkippedFiles            int     `json:"skipped_files"`
}

type validationModeCollector struct {
	mu sync.Mutex

	enabled                 bool
	suppressedFindings      int
	visibleFindings         int
	downgradedFindings      int
	falsePositiveCandidates int
	highConfidenceFindings  int
}

func newValidationModeCollector() *validationModeCollector {
	return &validationModeCollector{}
}

func (v *validationModeCollector) SetEnabled(enabled bool) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.enabled = enabled
}

func (v *validationModeCollector) RecordSuppressedFinding(_ scanner.SuppressedFinding) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.enabled {
		return
	}
	v.suppressedFindings++
}

func (v *validationModeCollector) RecordVisibleFinding(f scanner.Finding) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.enabled {
		return
	}
	v.visibleFindings++
	if f.Confidence == "high" {
		v.highConfidenceFindings++
	}
	if isFalsePositiveCandidate(f) {
		v.falsePositiveCandidates++
	}
}

func (v *validationModeCollector) RecordDowngradedFinding(_ scanner.Finding) {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.enabled {
		return
	}
	v.downgradedFindings++
}

func (v *validationModeCollector) Summary(snapshot summarySnapshot) *validationModeSummary {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.enabled {
		return nil
	}

	total := v.visibleFindings + v.suppressedFindings
	ratio := 0.0
	if v.visibleFindings > 0 {
		ratio = float64(v.highConfidenceFindings) / float64(v.visibleFindings)
	}

	return &validationModeSummary{
		Enabled:                 true,
		TotalFindings:           total,
		SuppressedFindings:      v.suppressedFindings,
		VisibleFindings:         v.visibleFindings,
		DowngradedFindings:      v.downgradedFindings,
		FalsePositiveCandidates: v.falsePositiveCandidates,
		HighConfidenceFindings:  v.highConfidenceFindings,
		HighConfidenceRatio:     ratio,
		SkippedFiles:            snapshot.SkippedFiles,
	}
}

func isFalsePositiveCandidate(f scanner.Finding) bool {
	if !f.Actionable {
		return true
	}
	switch f.TriageClass {
	case "config-only", "weak-review":
		return true
	}
	return f.Confidence == "low"
}

func SetValidationMode(sink scanner.FindingSink, enabled bool) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(ValidationModeAware); ok {
		aware.SetValidationMode(enabled)
	}
}

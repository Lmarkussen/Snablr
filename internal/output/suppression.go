package output

import (
	"sort"
	"strings"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/internal/suppression"
)

type SuppressionSummaryAware interface {
	SetSuppressionSummary(*suppressionSummary)
}

type ScanProfileAware interface {
	SetScanProfile(string)
}

type suppressionSummary struct {
	Enabled         bool                   `json:"enabled"`
	TotalSuppressed int                    `json:"total_suppressed"`
	Rules           []suppressionRuleCount `json:"rules,omitempty"`
	Samples         []suppressedFinding    `json:"samples,omitempty"`
}

type suppressionRuleCount struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Count       int    `json:"count"`
}

type suppressedFinding struct {
	Host                   string                 `json:"host,omitempty"`
	Share                  string                 `json:"share,omitempty"`
	FilePath               string                 `json:"file_path,omitempty"`
	RuleID                 string                 `json:"rule_id,omitempty"`
	Category               string                 `json:"category,omitempty"`
	Fingerprint            diff.FindingFingerprint `json:"fingerprint,omitempty"`
	SuppressionID          string                 `json:"suppression_id"`
	SuppressionDescription string                 `json:"suppression_description,omitempty"`
	SuppressionReason      string                 `json:"suppression_reason,omitempty"`
}

type suppressionWriter struct {
	inner       scanner.FindingSink
	matcher     *suppression.Matcher
	sampleLimit int
	suppressed  []suppressedFinding
}

func WrapWithSuppression(sink scanner.FindingSink, cfg config.SuppressionConfig) scanner.FindingSink {
	matcher := suppression.New(cfg.Rules)
	if sink == nil || matcher == nil {
		return sink
	}
	return &suppressionWriter{
		inner:       sink,
		matcher:     matcher,
		sampleLimit: cfg.SampleLimit,
		suppressed:  make([]suppressedFinding, 0),
	}
}

func (s *suppressionWriter) WriteFinding(f scanner.Finding) error {
	if item, ok := s.suppressedFinding(f); ok {
		s.suppressed = append(s.suppressed, item)
		return nil
	}
	return s.inner.WriteFinding(f)
}

func (s *suppressionWriter) Close() error {
	SetSuppressionSummary(s.inner, buildSuppressionSummary(s.suppressed, s.sampleLimit))
	return s.inner.Close()
}

func (s *suppressionWriter) RecordHost(host string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}
}

func (s *suppressionWriter) RecordShare(host, share string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordShare(host, share)
	}
}

func (s *suppressionWriter) RecordFile(meta scanner.FileMetadata) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordFile(meta)
	}
}

func (s *suppressionWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordSkip(meta, reason)
	}
}

func (s *suppressionWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordReadError(meta, err)
	}
}

func (s *suppressionWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	if aware, ok := s.inner.(MetricsAware); ok {
		aware.SetMetricsSnapshot(snapshot)
	}
}

func (s *suppressionWriter) SetBaselineFindings(findings []scanner.Finding) {
	if aware, ok := s.inner.(BaselineAware); ok {
		aware.SetBaselineFindings(findings)
	}
}

func (s *suppressionWriter) SetBaselinePerformance(summary *diff.PerformanceSummary) {
	if aware, ok := s.inner.(BaselinePerformanceAware); ok {
		aware.SetBaselinePerformance(summary)
	}
}

func (s *suppressionWriter) SetValidationManifest(path string) {
	if aware, ok := s.inner.(validationManifestAware); ok {
		aware.SetValidationManifest(path)
	}
}

func (s *suppressionWriter) SetValidationMode(enabled bool) {
	if aware, ok := s.inner.(ValidationModeAware); ok {
		aware.SetValidationMode(enabled)
	}
}

func (s *suppressionWriter) RecordSuppressedFinding(event scanner.SuppressedFinding) {
	if observer, ok := s.inner.(scanner.ValidationObserver); ok {
		observer.RecordSuppressedFinding(event)
	}
}

func (s *suppressionWriter) RecordVisibleFinding(finding scanner.Finding) {
	if _, ok := s.suppressedFinding(finding); ok {
		return
	}
	if observer, ok := s.inner.(scanner.ValidationObserver); ok {
		observer.RecordVisibleFinding(finding)
	}
}

func (s *suppressionWriter) RecordDowngradedFinding(finding scanner.Finding) {
	if _, ok := s.suppressedFinding(finding); ok {
		return
	}
	if observer, ok := s.inner.(scanner.ValidationObserver); ok {
		observer.RecordDowngradedFinding(finding)
	}
}

func (s *suppressionWriter) SetScanProfile(profile string) {
	if aware, ok := s.inner.(ScanProfileAware); ok {
		aware.SetScanProfile(profile)
	}
}

func (s *suppressionWriter) suppressedFinding(f scanner.Finding) (suppressedFinding, bool) {
	match, ok := s.matcher.Match(f)
	if !ok {
		return suppressedFinding{}, false
	}
	return suppressedFinding{
		Host:                   strings.TrimSpace(f.Host),
		Share:                  strings.TrimSpace(f.Share),
		FilePath:               strings.TrimSpace(f.FilePath),
		RuleID:                 strings.TrimSpace(f.RuleID),
		Category:               strings.TrimSpace(f.Category),
		Fingerprint:            diff.Fingerprint(f),
		SuppressionID:          match.SuppressionID,
		SuppressionDescription: match.SuppressionDescription,
		SuppressionReason:      match.SuppressionReason,
	}, true
}

func buildSuppressionSummary(items []suppressedFinding, sampleLimit int) *suppressionSummary {
	if len(items) == 0 {
		return nil
	}
	counts := make(map[string]suppressionRuleCount, len(items))
	for _, item := range items {
		current := counts[item.SuppressionID]
		current.ID = item.SuppressionID
		current.Description = item.SuppressionDescription
		current.Reason = item.SuppressionReason
		current.Count++
		counts[item.SuppressionID] = current
	}
	rules := make([]suppressionRuleCount, 0, len(counts))
	for _, item := range counts {
		rules = append(rules, item)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Count != rules[j].Count {
			return rules[i].Count > rules[j].Count
		}
		return strings.ToLower(rules[i].ID) < strings.ToLower(rules[j].ID)
	})

	samples := make([]suppressedFinding, len(items))
	copy(samples, items)
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].SuppressionID != samples[j].SuppressionID {
			return strings.ToLower(samples[i].SuppressionID) < strings.ToLower(samples[j].SuppressionID)
		}
		if samples[i].Host != samples[j].Host {
			return strings.ToLower(samples[i].Host) < strings.ToLower(samples[j].Host)
		}
		if samples[i].Share != samples[j].Share {
			return strings.ToLower(samples[i].Share) < strings.ToLower(samples[j].Share)
		}
		return strings.ToLower(samples[i].FilePath) < strings.ToLower(samples[j].FilePath)
	})
	if sampleLimit > 0 && len(samples) > sampleLimit {
		samples = samples[:sampleLimit]
	}

	return &suppressionSummary{
		Enabled:         true,
		TotalSuppressed: len(items),
		Rules:           rules,
		Samples:         samples,
	}
}

func SetSuppressionSummary(sink scanner.FindingSink, summary *suppressionSummary) {
	if sink == nil || summary == nil {
		return
	}
	if aware, ok := sink.(SuppressionSummaryAware); ok {
		aware.SetSuppressionSummary(summary)
	}
}

func SetScanProfile(sink scanner.FindingSink, profile string) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(ScanProfileAware); ok {
		aware.SetScanProfile(strings.TrimSpace(profile))
	}
}

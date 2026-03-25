package output

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type ConsoleWriter struct {
	w                   io.Writer
	closer              io.Closer
	mu                  sync.Mutex
	metrics             metrics.Snapshot
	summary             *summaryCollector
	findings            []scanner.Finding
	profile             string
	manifest            string
	suppression         *suppressionSummary
	baselinePerformance *diff.PerformanceSummary
	validationMode      *validationModeCollector
}

func NewConsoleWriter(w io.Writer, closer io.Closer) *ConsoleWriter {
	return &ConsoleWriter{
		w:              w,
		closer:         closer,
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
	}
}

func (c *ConsoleWriter) WriteFinding(f scanner.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.summary.RecordFinding(f)
	c.findings = append(c.findings, f)
	if !isPrimaryLiveFinding(f) {
		return nil
	}
	return c.writeFindingLocked(f)
}

func (c *ConsoleWriter) writeFindingLocked(f scanner.Finding) error {
	if _, err := fmt.Fprintf(c.w, "[%s] %s\n", strings.ToUpper(f.Severity), f.RuleID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Host: %s\n", valueOrDash(f.Host)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Share: %s\n", valueOrDash(f.Share)); err != nil {
		return err
	}
	if f.ShareType != "" {
		if _, err := fmt.Fprintf(c.w, "Share Type: %s\n", f.ShareType); err != nil {
			return err
		}
	}
	if f.ShareDescription != "" {
		if _, err := fmt.Fprintf(c.w, "Share Description: %s\n", f.ShareDescription); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Source: %s\n", valueOrDash(f.Source)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "File: %s\n", uncPath(f)); err != nil {
		return err
	}
	if f.ArchivePath != "" {
		if _, err := fmt.Fprintf(c.w, "Archive: %s\n", f.ArchivePath); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.w, "Archive Member: %s\n", valueOrDash(f.ArchiveMemberPath)); err != nil {
			return err
		}
		inspectionMode := "local"
		if !f.ArchiveLocalInspect {
			inspectionMode = "unknown"
		}
		if _, err := fmt.Fprintf(c.w, "Archive Inspection: %s\n", inspectionMode); err != nil {
			return err
		}
	}
	if f.DatabaseFilePath != "" || f.DatabaseTable != "" || f.DatabaseColumn != "" {
		if _, err := fmt.Fprintf(c.w, "Database File: %s\n", valueOrDash(f.DatabaseFilePath)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.w, "Database Table: %s\n", valueOrDash(f.DatabaseTable)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(c.w, "Database Column: %s\n", valueOrDash(f.DatabaseColumn)); err != nil {
			return err
		}
		if f.DatabaseRowContext != "" {
			if _, err := fmt.Fprintf(c.w, "Database Row Context: %s\n", f.DatabaseRowContext); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(c.w, "Rule: %s\n", f.RuleName); err != nil {
		return err
	}
	if f.Confidence != "" {
		if _, err := fmt.Fprintf(c.w, "Confidence: %s", strings.ToUpper(f.Confidence)); err != nil {
			return err
		}
		if f.ConfidenceScore > 0 {
			if _, err := fmt.Fprintf(c.w, " (%d)", f.ConfidenceScore); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(c.w); err != nil {
			return err
		}
	}
	if len(f.MatchedRuleIDs) > 0 {
		if _, err := fmt.Fprintf(c.w, "Matched Rules: %s\n", strings.Join(f.MatchedRuleIDs, ", ")); err != nil {
			return err
		}
	}
	if len(f.MatchedSignalTypes) > 0 {
		if _, err := fmt.Fprintf(c.w, "Signals: %s\n", strings.Join(f.MatchedSignalTypes, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Signal: %s\n", valueOrDash(primarySignalType(f))); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Category: %s\n", valueOrDash(f.Category)); err != nil {
		return err
	}
	if f.FromSYSVOL || f.FromNETLOGON {
		label := "NETLOGON"
		if f.FromSYSVOL {
			label = "SYSVOL"
		}
		if _, err := fmt.Fprintf(c.w, "AD Share: %s\n", label); err != nil {
			return err
		}
	}
	if f.DFSNamespacePath != "" {
		if _, err := fmt.Fprintf(c.w, "DFS Namespace: %s\n", f.DFSNamespacePath); err != nil {
			return err
		}
	}
	if f.DFSLinkPath != "" {
		if _, err := fmt.Fprintf(c.w, "DFS Link: %s\n", f.DFSLinkPath); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Tags: %s\n", tagsOrDash(f.Tags)); err != nil {
		return err
	}
	for _, line := range consoleEvidenceLines(f) {
		if _, err := fmt.Fprintln(c.w, line); err != nil {
			return err
		}
	}
	if f.MatchReason != "" {
		if _, err := fmt.Fprintf(c.w, "Why It Matched: %s\n", f.MatchReason); err != nil {
			return err
		}
	}
	if len(f.ConfidenceReasons) > 0 {
		if _, err := fmt.Fprintf(c.w, "Confidence Raised By: %s\n", strings.Join(limitStrings(f.ConfidenceReasons, 3), "; ")); err != nil {
			return err
		}
	}
	if f.RuleExplanation != "" {
		if _, err := fmt.Fprintf(c.w, "Rule Note: %s\n", f.RuleExplanation); err != nil {
			return err
		}
	}
	guidance := f.RuleRemediation
	if guidance == "" {
		guidance = remediationGuidanceForCategory(f.Category)
	}
	if guidance != "" {
		if _, err := fmt.Fprintf(c.w, "Remediation: %s\n", guidance); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(c.w)
	return err
}

func limitStrings(values []string, max int) []string {
	if len(values) <= max || max <= 0 {
		return values
	}
	return values[:max]
}

func (c *ConsoleWriter) RecordHost(host string) {
	c.summary.RecordHost(host)
}

func (c *ConsoleWriter) RecordShare(host, share string) {
	c.summary.RecordShare(host, share)
}

func (c *ConsoleWriter) RecordFile(meta scanner.FileMetadata) {
	c.summary.RecordFile(meta)
}

func (c *ConsoleWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	c.summary.RecordSkip(meta, reason)
}

func (c *ConsoleWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	c.summary.RecordReadError(meta, err)
}

func (c *ConsoleWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = snapshot
}

func (c *ConsoleWriter) SetValidationManifest(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.manifest = path
}

func (c *ConsoleWriter) SetSuppressionSummary(summary *suppressionSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.suppression = summary
}

func (c *ConsoleWriter) SetScanProfile(profile string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profile = strings.TrimSpace(profile)
}

func (c *ConsoleWriter) SetValidationMode(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.validationMode.SetEnabled(enabled)
}

func (c *ConsoleWriter) RecordSuppressedFinding(event scanner.SuppressedFinding) {
	c.validationMode.RecordSuppressedFinding(event)
}

func (c *ConsoleWriter) RecordVisibleFinding(f scanner.Finding) {
	c.validationMode.RecordVisibleFinding(f)
}

func (c *ConsoleWriter) RecordDowngradedFinding(f scanner.Finding) {
	c.validationMode.RecordDowngradedFinding(f)
}

func (c *ConsoleWriter) SetBaselinePerformance(summary *diff.PerformanceSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if summary == nil {
		c.baselinePerformance = nil
		return
	}
	clone := *summary
	clone.ClassificationDistribution = append([]diff.ClassificationSummary{}, summary.ClassificationDistribution...)
	c.baselinePerformance = &clone
}

func (c *ConsoleWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	augmented := augmentFindingsForReporting(c.findings)
	existing := make(map[string]struct{}, len(c.findings))
	for _, finding := range c.findings {
		existing[correlationFindingKey(finding)] = struct{}{}
	}
	for _, finding := range augmented {
		key := correlationFindingKey(finding)
		if _, ok := existing[key]; ok {
			continue
		}
		if err := c.writeFindingLocked(finding); err != nil {
			return err
		}
	}

	snapshot := adjustedSummarySnapshot(c.summary.Snapshot(), c.findings, augmented)
	if _, err := fmt.Fprintf(c.w, "Summary: hosts=%d shares=%d files=%d matches=%d skipped=%d read_errors=%d started=%s ended=%s\n",
		snapshot.HostsScanned,
		snapshot.SharesScanned,
		snapshot.FilesScanned,
		snapshot.MatchesFound,
		snapshot.SkippedFiles,
		snapshot.ReadErrors,
		snapshot.StartedAt.Format(timeFormat),
		snapshot.EndedAt.Format(timeFormat),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Profile: %s\n", valueOrDash(c.profile)); err != nil {
		return err
	}
	if c.metrics.Counters.TargetsLoaded > 0 || c.metrics.Counters.TargetsReachable > 0 || c.metrics.Counters.SharesEnumerated > 0 {
		if _, err := fmt.Fprintf(c.w, "Metrics: targets_loaded=%d targets_reachable=%d shares_enumerated=%d files_visited=%d files_skipped=%d files_read=%d matches_found=%d\n",
			c.metrics.Counters.TargetsLoaded,
			c.metrics.Counters.TargetsReachable,
			c.metrics.Counters.SharesEnumerated,
			c.metrics.Counters.FilesVisited,
			c.metrics.Counters.FilesSkipped,
			c.metrics.Counters.FilesRead,
			c.metrics.Counters.MatchesFound,
		); err != nil {
			return err
		}
	}
	if len(c.metrics.Phases) > 0 {
		if _, err := fmt.Fprintln(c.w, "Phase Timings:"); err != nil {
			return err
		}
		for _, phase := range c.metrics.Phases {
			if _, err := fmt.Fprintf(c.w, "  %s: %dms\n", phase.Name, phase.DurationMS); err != nil {
				return err
			}
		}
	}
	performanceSummary := buildPerformanceSummary(snapshot, augmented)
	if _, err := fmt.Fprintf(c.w, "Performance: files_scanned=%d findings=%d duration_ms=%d files_per_second=%.2f\n",
		performanceSummary.FilesScanned,
		performanceSummary.FindingsTotal,
		performanceSummary.DurationMS,
		performanceSummary.FilesPerSecond,
	); err != nil {
		return err
	}
	if len(performanceSummary.ClassificationDistribution) > 0 {
		if _, err := fmt.Fprintf(c.w, "Classification Distribution: %s\n", formatClassificationSummary(performanceSummary.ClassificationDistribution)); err != nil {
			return err
		}
	}
	if comparison := buildPerformanceComparison(performanceSummary, c.baselinePerformance); comparison != nil {
		if _, err := fmt.Fprintf(c.w, "Performance Comparison: findings_delta=%+d duration_delta_ms=%+d files_per_second_delta=%+.2f\n",
			comparison.FindingsDelta,
			comparison.DurationDeltaMS,
			comparison.FilesPerSecondDelta,
		); err != nil {
			return err
		}
		if len(comparison.ClassificationChanges) > 0 {
			if _, err := fmt.Fprintf(c.w, "Classification Changes: %s\n", formatClassificationDeltas(comparison.ClassificationChanges)); err != nil {
				return err
			}
		}
	}
	accessPaths := buildAccessPathSummaries(augmented)
	if len(accessPaths) > 0 {
		if _, err := fmt.Fprintf(c.w, "Top Access Paths: showing %d of %d ranked clusters\n", len(topAccessPaths(accessPaths, 5)), len(accessPaths)); err != nil {
			return err
		}
		for _, item := range topAccessPaths(accessPaths, 5) {
			if _, err := fmt.Fprintf(c.w, "  %d. [%s %d] %s\n",
				item.Rank,
				strings.ToUpper(valueOrDash(item.PriorityTier)),
				item.ExploitabilityScore,
				item.Label,
			); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(c.w, "    Type: %s\n", valueOrDash(item.Type)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(c.w, "    Host/Share: %s/%s\n",
				valueOrDash(item.Host),
				valueOrDash(item.Share),
			); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(c.w, "    Primary: %s\n", item.PrimaryPath); err != nil {
				return err
			}
			if item.Completeness != "" {
				if _, err := fmt.Fprintf(c.w, "    Completeness: %s\n", item.Completeness); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(c.w, "    Why: %s\n", item.WhyItMatters); err != nil {
				return err
			}
			if item.AccessHint != "" {
				if _, err := fmt.Fprintf(c.w, "    Enables: %s\n", item.AccessHint); err != nil {
					return err
				}
			}
			if len(item.RelatedArtifacts) > 0 {
				if _, err := fmt.Fprintf(c.w, "    Related: %s\n", strings.Join(limitStrings(item.RelatedArtifacts, 3), "; ")); err != nil {
					return err
				}
			}
		}
	}
	if validationMode := c.validationMode.Summary(snapshot); validationMode != nil {
		if _, err := fmt.Fprintf(c.w, "Validation Mode: total=%d suppressed=%d visible=%d downgraded=%d false_positive_candidates=%d high_confidence=%d high_confidence_ratio=%.2f skipped_files=%d\n",
			validationMode.TotalFindings,
			validationMode.SuppressedFindings,
			validationMode.VisibleFindings,
			validationMode.DowngradedFindings,
			validationMode.FalsePositiveCandidates,
			validationMode.HighConfidenceFindings,
			validationMode.HighConfidenceRatio,
			validationMode.SkippedFiles,
		); err != nil {
			return err
		}
	}
	if c.suppression != nil && c.suppression.TotalSuppressed > 0 {
		if _, err := fmt.Fprintf(c.w, "Suppressed Findings: total=%d rules=%d\n", c.suppression.TotalSuppressed, len(c.suppression.Rules)); err != nil {
			return err
		}
		for _, item := range limitSuppressionRules(c.suppression.Rules, 5) {
			if _, err := fmt.Fprintf(c.w, "  %s: count=%d %s\n", item.ID, item.Count, valueOrDash(item.Reason)); err != nil {
				return err
			}
		}
		for _, item := range limitSuppressedFindings(c.suppression.Samples, 5) {
			if _, err := fmt.Fprintf(c.w, "  sample: [%s] %s/%s/%s rule=%s %s\n",
				item.SuppressionID,
				valueOrDash(item.Host),
				valueOrDash(item.Share),
				item.FilePath,
				valueOrDash(item.RuleID),
				valueOrDash(item.SuppressionReason),
			); err != nil {
				return err
			}
		}
	}

	validation, err := buildValidationSummary(c.manifest, augmented)
	if err != nil {
		return err
	}
	if validation != nil && validation.HasValidation {
		if _, err := fmt.Fprintf(c.w, "Validation: expected=%d found=%d missed=%d unexpected=%d suppressed_config_only=%d promoted_actionable=%d promoted_correlated=%d\n",
			validation.ExpectedItems,
			validation.FoundItems,
			validation.MissedItems,
			validation.UnexpectedFindings,
			validation.SuppressedConfigOnly,
			validation.PromotedActionable,
			validation.PromotedCorrelated,
		); err != nil {
			return err
		}
		if len(validation.ClassCoverage) > 0 {
			if _, err := fmt.Fprintln(c.w, "Validation Classes:"); err != nil {
				return err
			}
			for _, class := range validation.ClassCoverage {
				if _, err := fmt.Fprintf(c.w, "  %s: planted=%d detected=%d missed=%d matched=%d suppressed=%d downgraded=%d promoted=%d mismatched=%d\n",
					class.Label,
					class.Planted,
					class.Detected,
					class.Missed,
					class.Matched,
					class.Suppressed,
					class.Downgraded,
					class.Promoted,
					class.Mismatched,
				); err != nil {
					return err
				}
			}
		}
		if len(validation.MissedExpected) > 0 {
			if _, err := fmt.Fprintln(c.w, "Validation Missed:"); err != nil {
				return err
			}
			for _, item := range limitValidationItems(validation.MissedExpected, 5) {
				if _, err := fmt.Fprintf(c.w, "  [%s] %s/%s/%s %s\n", item.Label, valueOrDash(item.Host), valueOrDash(item.Share), item.Path, item.Reason); err != nil {
					return err
				}
			}
		}
		if len(validation.OverPromoted) > 0 {
			if _, err := fmt.Fprintln(c.w, "Validation Over-Promoted:"); err != nil {
				return err
			}
			for _, item := range limitValidationItems(validation.OverPromoted, 5) {
				if _, err := fmt.Fprintf(c.w, "  [%s] %s/%s/%s observed=%s confidence=%s correlated=%t %s\n",
					item.Label,
					valueOrDash(item.Host),
					valueOrDash(item.Share),
					item.Path,
					valueOrDash(item.ObservedTriageClass),
					valueOrDash(item.ObservedConfidence),
					item.ObservedCorrelated,
					item.Reason,
				); err != nil {
					return err
				}
			}
		}
	}

	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func limitValidationItems(values []validationItem, max int) []validationItem {
	if len(values) <= max || max <= 0 {
		return values
	}
	return values[:max]
}

func limitSuppressionRules(values []suppressionRuleCount, max int) []suppressionRuleCount {
	if len(values) <= max || max <= 0 {
		return values
	}
	return values[:max]
}

func limitSuppressedFindings(values []suppressedFinding, max int) []suppressedFinding {
	if len(values) <= max || max <= 0 {
		return values
	}
	return values[:max]
}

func formatClassificationSummary(values []diff.ClassificationSummary) string {
	parts := make([]string, 0, len(values))
	for _, item := range values {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Class, item.Count))
	}
	return strings.Join(parts, ", ")
}

func formatClassificationDeltas(values []diff.ClassificationDelta) string {
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if item.Delta == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%+d", item.Class, item.Delta))
	}
	if len(parts) == 0 {
		return "no material classification changes"
	}
	return strings.Join(parts, ", ")
}

func consoleEvidenceLines(f scanner.Finding) []string {
	signalType := primarySignalType(f)
	switch signalType {
	case "validated", "content":
		lines := make([]string, 0, 5)
		if f.LineNumber > 0 {
			lines = append(lines, fmt.Sprintf("Line: %d", f.LineNumber))
		}
		if f.PotentialAccount != "" {
			lines = append(lines, fmt.Sprintf("Potential account context: %s", f.PotentialAccount))
		}
		if value := firstNonEmpty(f.MatchedText, f.MatchedTextRedacted, f.Match); value != "" {
			label := "Matched text"
			if signalType == "validated" {
				label = "Validated detail"
			}
			lines = append(lines, fmt.Sprintf("%s: %s", label, value))
		}
		if value := firstNonEmpty(f.Context, f.ContextRedacted, f.Snippet); value != "" {
			lines = append(lines, "Context:")
			for _, rawLine := range strings.Split(value, "\n") {
				lines = append(lines, "  "+rawLine)
			}
		}
		return lines
	case "filename":
		if value := firstNonEmpty(f.MatchedText, f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched filename token: %s", value)}
		}
	case "extension":
		if value := firstNonEmpty(f.MatchedText, f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched extension: %s", value)}
		}
	case "path", "directory":
		if value := firstNonEmpty(f.MatchedText, f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched %s token: %s", signalType, value)}
		}
	}

	if value := firstNonEmpty(f.MatchedText, f.MatchedTextRedacted, f.Match); value != "" {
		return []string{fmt.Sprintf("Matched value: %s", value)}
	}
	if f.Snippet != "" {
		return []string{fmt.Sprintf("Snippet: %s", f.Snippet)}
	}
	return nil
}

func primarySignalType(f scanner.Finding) string {
	if strings.TrimSpace(f.SignalType) != "" {
		return strings.TrimSpace(f.SignalType)
	}
	if len(f.MatchedSignalTypes) > 0 {
		return strings.TrimSpace(f.MatchedSignalTypes[0])
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

package output

import (
	"encoding/json"
	"io"
	"strings"
	"sync"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type JSONWriter struct {
	closer              io.Closer
	findings            []scanner.Finding
	baseline            []scanner.Finding
	baselinePerformance *diff.PerformanceSummary
	mu                  sync.Mutex
	pretty              bool
	metrics             metrics.Snapshot
	summary             *summaryCollector
	profile             string
	manifest            string
	suppression         *suppressionSummary
	validationMode      *validationModeCollector
	backupArtifacts     *backupArtifactCollector
	w                   io.Writer
}

func NewJSONWriter(w io.Writer, closer io.Closer, pretty bool) *JSONWriter {
	return &JSONWriter{
		w:               w,
		closer:          closer,
		pretty:          pretty,
		summary:         newSummaryCollector(),
		validationMode:  newValidationModeCollector(),
		backupArtifacts: newBackupArtifactCollector(),
	}
}

func (j *JSONWriter) WriteFinding(f scanner.Finding) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.summary.RecordFinding(f)
	j.findings = append(j.findings, f)
	return nil
}

func (j *JSONWriter) RecordHost(host string) {
	j.summary.RecordHost(host)
}

func (j *JSONWriter) RecordShare(host, share string) {
	j.summary.RecordShare(host, share)
}

func (j *JSONWriter) RecordFile(meta scanner.FileMetadata) {
	j.summary.RecordFile(meta)
	j.backupArtifacts.RecordFile(meta)
}

func (j *JSONWriter) SetBackupArtifactInventoryEnabled(enabled bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.backupArtifacts.SetEnabled(enabled)
}

func (j *JSONWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	j.summary.RecordSkip(meta, reason)
}

func (j *JSONWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	j.summary.RecordReadError(meta, err)
}

func (j *JSONWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.metrics = snapshot
}

func (j *JSONWriter) SetBaselineFindings(findings []scanner.Finding) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.baseline = cloneFindings(findings)
}

func (j *JSONWriter) SetBaselinePerformance(summary *diff.PerformanceSummary) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if summary == nil {
		j.baselinePerformance = nil
		return
	}
	clone := *summary
	clone.ClassificationDistribution = append([]diff.ClassificationSummary{}, summary.ClassificationDistribution...)
	j.baselinePerformance = &clone
}

func (j *JSONWriter) SetValidationManifest(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.manifest = path
}

func (j *JSONWriter) SetSuppressionSummary(summary *suppressionSummary) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.suppression = summary
}

func (j *JSONWriter) SetScanProfile(profile string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.profile = profile
}

func (j *JSONWriter) SetValidationMode(enabled bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.validationMode.SetEnabled(enabled)
}

func (j *JSONWriter) RecordSuppressedFinding(event scanner.SuppressedFinding) {
	j.validationMode.RecordSuppressedFinding(event)
}

func (j *JSONWriter) RecordVisibleFinding(f scanner.Finding) {
	j.validationMode.RecordVisibleFinding(f)
}

func (j *JSONWriter) RecordDowngradedFinding(f scanner.Finding) {
	j.validationMode.RecordDowngradedFinding(f)
}

func (j *JSONWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	enc := json.NewEncoder(j.w)
	if j.pretty {
		enc.SetIndent("", "  ")
	}

	var diffResult *diff.DiffResult
	var statusByFingerprint map[diff.FindingFingerprint]diff.FindingDelta
	augmented := augmentFindingsForReporting(j.findings)
	if len(j.baseline) > 0 {
		result := diff.Compare(j.baseline, augmented)
		diffResult = &result
		statusByFingerprint = diff.CurrentStatuses(result)
	}

	report := jsonReport{
		Profile:                 strings.TrimSpace(j.profile),
		Summary:                 adjustedSummarySnapshot(j.summary.Snapshot(), j.findings, augmented),
		Metrics:                 j.metrics,
		CategorySummaries:       buildCategorySummaries(augmented),
		AccessPaths:             buildAccessPathSummaries(augmented),
		Suppression:             j.suppression,
		BackupArtifactInventory: j.backupArtifacts.Snapshot(),
		Findings:                make([]jsonFinding, 0, len(augmented)),
	}
	performanceSummary := buildPerformanceSummary(report.Summary, augmented)
	report.Performance = performanceSummaryToJSON(performanceSummary)
	report.PerformanceComparison = performanceComparisonToJSON(buildPerformanceComparison(performanceSummary, j.baselinePerformance))
	report.ValidationMode = j.validationMode.Summary(report.Summary)
	validation, err := buildValidationSummary(j.manifest, augmented)
	if err != nil {
		if j.closer != nil {
			_ = j.closer.Close()
		}
		return err
	}
	report.Validation = validation
	for _, finding := range augmented {
		report.Findings = append(report.Findings, toJSONFinding(finding, statusByFingerprint[diff.Fingerprint(finding)]))
	}
	if diffResult != nil {
		report.DiffSummary = &jsonDiffSummary{
			New:       diffResult.Summary().New,
			Removed:   diffResult.Summary().Removed,
			Changed:   diffResult.Summary().Changed,
			Unchanged: diffResult.Summary().Unchanged,
		}
	}

	if err := enc.Encode(report); err != nil {
		if j.closer != nil {
			_ = j.closer.Close()
		}
		return err
	}
	if j.closer == nil {
		return nil
	}
	return j.closer.Close()
}

type jsonReport struct {
	Profile                 string                   `json:"profile,omitempty"`
	Summary                 summarySnapshot          `json:"summary"`
	Metrics                 metrics.Snapshot         `json:"metrics"`
	CategorySummaries       []categorySummary        `json:"category_summaries,omitempty"`
	AccessPaths             []accessPathSummary      `json:"access_paths,omitempty"`
	Suppression             *suppressionSummary      `json:"suppression,omitempty"`
	BackupArtifactInventory *backupArtifactInventory `json:"backup_artifact_inventory,omitempty"`
	DiffSummary             *jsonDiffSummary         `json:"diff_summary,omitempty"`
	Performance             *jsonPerformanceSummary  `json:"performance,omitempty"`
	PerformanceComparison   *jsonPerformanceCompare  `json:"performance_comparison,omitempty"`
	ValidationMode          *validationModeSummary   `json:"validation_mode,omitempty"`
	Validation              *validationSummary       `json:"validation,omitempty"`
	Findings                []jsonFinding            `json:"findings"`
}

type jsonPerformanceSummary struct {
	FilesScanned               int                          `json:"files_scanned"`
	FindingsTotal              int                          `json:"findings_total"`
	DurationMS                 int64                        `json:"duration_ms"`
	FilesPerSecond             float64                      `json:"files_per_second"`
	ClassificationDistribution []diff.ClassificationSummary `json:"classification_distribution,omitempty"`
}

type jsonPerformanceCompare struct {
	FindingsDelta         int                        `json:"findings_delta"`
	DurationDeltaMS       int64                      `json:"duration_delta_ms"`
	FilesPerSecondDelta   float64                    `json:"files_per_second_delta"`
	ClassificationChanges []diff.ClassificationDelta `json:"classification_changes,omitempty"`
}

type jsonDiffSummary struct {
	New       int `json:"new"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

type jsonFinding struct {
	Host                string                      `json:"host,omitempty"`
	Share               string                      `json:"share,omitempty"`
	ShareDescription    string                      `json:"share_description,omitempty"`
	ShareType           string                      `json:"share_type,omitempty"`
	FilePath            string                      `json:"file_path"`
	Source              string                      `json:"source,omitempty"`
	ArchivePath         string                      `json:"archive_path,omitempty"`
	ArchiveMemberPath   string                      `json:"archive_member_path,omitempty"`
	ArchiveLocalInspect bool                        `json:"archive_local_inspect,omitempty"`
	DatabaseFilePath    string                      `json:"database_file_path,omitempty"`
	DatabaseTable       string                      `json:"database_table,omitempty"`
	DatabaseColumn      string                      `json:"database_column,omitempty"`
	DatabaseRowContext  string                      `json:"database_row_context,omitempty"`
	DFSNamespacePath    string                      `json:"dfs_namespace_path,omitempty"`
	DFSLinkPath         string                      `json:"dfs_link_path,omitempty"`
	RuleID              string                      `json:"rule_id"`
	RuleName            string                      `json:"rule_name"`
	Severity            string                      `json:"severity"`
	Confidence          string                      `json:"confidence,omitempty"`
	RuleConfidence      string                      `json:"rule_confidence,omitempty"`
	ConfidenceScore     int                         `json:"confidence_score,omitempty"`
	ConfidenceReasons   []string                    `json:"confidence_reasons,omitempty"`
	Category            string                      `json:"category"`
	TriageClass         string                      `json:"triage_class,omitempty"`
	Actionable          bool                        `json:"actionable,omitempty"`
	Correlated          bool                        `json:"correlated,omitempty"`
	ConfidenceBreakdown scanner.ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`
	SharePriority       int                         `json:"share_priority,omitempty"`
	SharePriorityReason string                      `json:"share_priority_reason,omitempty"`
	FromSYSVOL          bool                        `json:"from_sysvol,omitempty"`
	FromNETLOGON        bool                        `json:"from_netlogon,omitempty"`
	MatchedRuleIDs      []string                    `json:"matched_rule_ids,omitempty"`
	MatchedSignalTypes  []string                    `json:"matched_signal_types,omitempty"`
	SupportingSignals   []scanner.SupportingSignal  `json:"supporting_signals,omitempty"`
	Tags                []string                    `json:"tags,omitempty"`
	SignalType          string                      `json:"signal_type,omitempty"`
	Match               string                      `json:"match,omitempty"`
	MatchedText         string                      `json:"matched_text,omitempty"`
	MatchedTextRedacted string                      `json:"matched_text_redacted,omitempty"`
	Snippet             string                      `json:"snippet,omitempty"`
	Context             string                      `json:"context,omitempty"`
	ContextRedacted     string                      `json:"context_redacted,omitempty"`
	PotentialAccount    string                      `json:"potential_account,omitempty"`
	LineNumber          int                         `json:"line_number,omitempty"`
	MatchSnippet        string                      `json:"match_snippet,omitempty"`
	MatchReason         string                      `json:"match_reason,omitempty"`
	RuleExplanation     string                      `json:"rule_explanation,omitempty"`
	RuleRemediation     string                      `json:"rule_remediation,omitempty"`
	RemediationGuidance string                      `json:"remediation_guidance,omitempty"`
	DiffStatus          string                      `json:"diff_status,omitempty"`
	ChangedFields       []string                    `json:"changed_fields,omitempty"`
}

func toJSONFinding(f scanner.Finding, delta diff.FindingDelta) jsonFinding {
	return jsonFinding{
		Host:                f.Host,
		Share:               f.Share,
		ShareDescription:    f.ShareDescription,
		ShareType:           f.ShareType,
		FilePath:            f.FilePath,
		Source:              f.Source,
		ArchivePath:         f.ArchivePath,
		ArchiveMemberPath:   f.ArchiveMemberPath,
		ArchiveLocalInspect: f.ArchiveLocalInspect,
		DatabaseFilePath:    f.DatabaseFilePath,
		DatabaseTable:       f.DatabaseTable,
		DatabaseColumn:      f.DatabaseColumn,
		DatabaseRowContext:  f.DatabaseRowContext,
		DFSNamespacePath:    f.DFSNamespacePath,
		DFSLinkPath:         f.DFSLinkPath,
		RuleID:              f.RuleID,
		RuleName:            f.RuleName,
		Severity:            f.Severity,
		Confidence:          f.Confidence,
		RuleConfidence:      f.RuleConfidence,
		ConfidenceScore:     f.ConfidenceScore,
		ConfidenceReasons:   append([]string{}, f.ConfidenceReasons...),
		Category:            f.Category,
		TriageClass:         f.TriageClass,
		Actionable:          f.Actionable,
		Correlated:          f.Correlated,
		ConfidenceBreakdown: f.ConfidenceBreakdown,
		SharePriority:       f.SharePriority,
		SharePriorityReason: f.SharePriorityReason,
		FromSYSVOL:          f.FromSYSVOL,
		FromNETLOGON:        f.FromNETLOGON,
		MatchedRuleIDs:      append([]string{}, f.MatchedRuleIDs...),
		MatchedSignalTypes:  append([]string{}, f.MatchedSignalTypes...),
		SupportingSignals:   append([]scanner.SupportingSignal{}, f.SupportingSignals...),
		Tags:                append([]string{}, f.Tags...),
		SignalType:          f.SignalType,
		Match:               f.Match,
		MatchedText:         f.MatchedText,
		MatchedTextRedacted: f.MatchedTextRedacted,
		Snippet:             f.Snippet,
		Context:             f.Context,
		ContextRedacted:     f.ContextRedacted,
		PotentialAccount:    f.PotentialAccount,
		LineNumber:          f.LineNumber,
		MatchSnippet:        f.Snippet,
		MatchReason:         f.MatchReason,
		RuleExplanation:     f.RuleExplanation,
		RuleRemediation:     f.RuleRemediation,
		RemediationGuidance: remediationGuidanceForCategory(f.Category),
		DiffStatus:          string(delta.Status),
		ChangedFields:       append([]string{}, delta.ChangedFields...),
	}
}

func cloneFindings(findings []scanner.Finding) []scanner.Finding {
	out := make([]scanner.Finding, 0, len(findings))
	for _, finding := range findings {
		clone := finding
		clone.Tags = append([]string{}, finding.Tags...)
		out = append(out, clone)
	}
	return out
}

func performanceSummaryToJSON(summary diff.PerformanceSummary) *jsonPerformanceSummary {
	return &jsonPerformanceSummary{
		FilesScanned:               summary.FilesScanned,
		FindingsTotal:              summary.FindingsTotal,
		DurationMS:                 summary.DurationMS,
		FilesPerSecond:             summary.FilesPerSecond,
		ClassificationDistribution: append([]diff.ClassificationSummary{}, summary.ClassificationDistribution...),
	}
}

func performanceComparisonToJSON(comparison *diff.PerformanceComparison) *jsonPerformanceCompare {
	if comparison == nil {
		return nil
	}
	return &jsonPerformanceCompare{
		FindingsDelta:         comparison.FindingsDelta,
		DurationDeltaMS:       comparison.DurationDeltaMS,
		FilesPerSecondDelta:   comparison.FilesPerSecondDelta,
		ClassificationChanges: append([]diff.ClassificationDelta{}, comparison.ClassificationChanges...),
	}
}

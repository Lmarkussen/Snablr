package output

import (
	"encoding/json"
	"io"
	"sync"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type JSONWriter struct {
	closer   io.Closer
	findings []scanner.Finding
	baseline []scanner.Finding
	mu       sync.Mutex
	pretty   bool
	metrics  metrics.Snapshot
	summary  *summaryCollector
	w        io.Writer
}

func NewJSONWriter(w io.Writer, closer io.Closer, pretty bool) *JSONWriter {
	return &JSONWriter{
		w:       w,
		closer:  closer,
		pretty:  pretty,
		summary: newSummaryCollector(),
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

func (j *JSONWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	enc := json.NewEncoder(j.w)
	if j.pretty {
		enc.SetIndent("", "  ")
	}

	var diffResult *diff.DiffResult
	var statusByFingerprint map[diff.FindingFingerprint]diff.FindingDelta
	if len(j.baseline) > 0 {
		result := diff.Compare(j.baseline, j.findings)
		diffResult = &result
		statusByFingerprint = diff.CurrentStatuses(result)
	}

	report := jsonReport{
		Summary:           j.summary.Snapshot(),
		Metrics:           j.metrics,
		CategorySummaries: buildCategorySummaries(j.findings),
		Findings:          make([]jsonFinding, 0, len(j.findings)),
	}
	for _, finding := range j.findings {
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
	Summary           summarySnapshot   `json:"summary"`
	Metrics           metrics.Snapshot  `json:"metrics"`
	CategorySummaries []categorySummary `json:"category_summaries,omitempty"`
	DiffSummary       *jsonDiffSummary  `json:"diff_summary,omitempty"`
	Findings          []jsonFinding     `json:"findings"`
}

type jsonDiffSummary struct {
	New       int `json:"new"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

type jsonFinding struct {
	Host                string                     `json:"host,omitempty"`
	Share               string                     `json:"share,omitempty"`
	ShareDescription    string                     `json:"share_description,omitempty"`
	ShareType           string                     `json:"share_type,omitempty"`
	FilePath            string                     `json:"file_path"`
	Source              string                     `json:"source,omitempty"`
	DFSNamespacePath    string                     `json:"dfs_namespace_path,omitempty"`
	DFSLinkPath         string                     `json:"dfs_link_path,omitempty"`
	RuleID              string                     `json:"rule_id"`
	RuleName            string                     `json:"rule_name"`
	Severity            string                     `json:"severity"`
	Confidence          string                     `json:"confidence,omitempty"`
	RuleConfidence      string                     `json:"rule_confidence,omitempty"`
	ConfidenceScore     int                        `json:"confidence_score,omitempty"`
	ConfidenceReasons   []string                   `json:"confidence_reasons,omitempty"`
	Category            string                     `json:"category"`
	SharePriority       int                        `json:"share_priority,omitempty"`
	SharePriorityReason string                     `json:"share_priority_reason,omitempty"`
	FromSYSVOL          bool                       `json:"from_sysvol,omitempty"`
	FromNETLOGON        bool                       `json:"from_netlogon,omitempty"`
	MatchedRuleIDs      []string                   `json:"matched_rule_ids,omitempty"`
	MatchedSignalTypes  []string                   `json:"matched_signal_types,omitempty"`
	SupportingSignals   []scanner.SupportingSignal `json:"supporting_signals,omitempty"`
	Tags                []string                   `json:"tags,omitempty"`
	Match               string                     `json:"match,omitempty"`
	MatchSnippet        string                     `json:"match_snippet,omitempty"`
	MatchReason         string                     `json:"match_reason,omitempty"`
	RuleExplanation     string                     `json:"rule_explanation,omitempty"`
	RuleRemediation     string                     `json:"rule_remediation,omitempty"`
	RemediationGuidance string                     `json:"remediation_guidance,omitempty"`
	DiffStatus          string                     `json:"diff_status,omitempty"`
	ChangedFields       []string                   `json:"changed_fields,omitempty"`
}

func toJSONFinding(f scanner.Finding, delta diff.FindingDelta) jsonFinding {
	return jsonFinding{
		Host:                f.Host,
		Share:               f.Share,
		ShareDescription:    f.ShareDescription,
		ShareType:           f.ShareType,
		FilePath:            f.FilePath,
		Source:              f.Source,
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
		SharePriority:       f.SharePriority,
		SharePriorityReason: f.SharePriorityReason,
		FromSYSVOL:          f.FromSYSVOL,
		FromNETLOGON:        f.FromNETLOGON,
		MatchedRuleIDs:      append([]string{}, f.MatchedRuleIDs...),
		MatchedSignalTypes:  append([]string{}, f.MatchedSignalTypes...),
		SupportingSignals:   append([]scanner.SupportingSignal{}, f.SupportingSignals...),
		Tags:                append([]string{}, f.Tags...),
		Match:               f.Match,
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

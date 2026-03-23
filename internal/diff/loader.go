package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"snablr/internal/scanner"
)

type scanResultFile struct {
	Summary     scanResultSummary   `json:"summary"`
	Performance *PerformanceSummary `json:"performance,omitempty"`
	Findings    []scanResultFinding `json:"findings"`
}

type scanResultSummary struct {
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
	FilesScanned int       `json:"files_scanned"`
	MatchesFound int       `json:"matches_found"`
}

type scanResultFinding struct {
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
	SignalType          string                      `json:"signal_type,omitempty"`
	MatchedText         string                      `json:"matched_text,omitempty"`
	MatchedTextRedacted string                      `json:"matched_text_redacted,omitempty"`
	Context             string                      `json:"context,omitempty"`
	ContextRedacted     string                      `json:"context_redacted,omitempty"`
	PotentialAccount    string                      `json:"potential_account,omitempty"`
	LineNumber          int                         `json:"line_number,omitempty"`
	MatchedRuleIDs      []string                    `json:"matched_rule_ids,omitempty"`
	MatchedSignalTypes  []string                    `json:"matched_signal_types,omitempty"`
	SupportingSignals   []scanner.SupportingSignal  `json:"supporting_signals,omitempty"`
	FromSYSVOL          bool                        `json:"from_sysvol,omitempty"`
	FromNETLOGON        bool                        `json:"from_netlogon,omitempty"`
	Tags                []string                    `json:"tags,omitempty"`
	Match               string                      `json:"match,omitempty"`
	MatchSnippet        string                      `json:"match_snippet,omitempty"`
	MatchReason         string                      `json:"match_reason,omitempty"`
	RuleExplanation     string                      `json:"rule_explanation,omitempty"`
	RuleRemediation     string                      `json:"rule_remediation,omitempty"`
}

func LoadJSON(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, fmt.Errorf("read %s: %w", path, err)
	}

	var parsed scanResultFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Report{}, fmt.Errorf("parse %s: %w", path, err)
	}

	report := Report{
		Findings: make([]scanner.Finding, 0, len(parsed.Findings)),
	}
	for _, finding := range parsed.Findings {
		report.Findings = append(report.Findings, scanner.Finding{
			Host:                finding.Host,
			Share:               finding.Share,
			ShareDescription:    finding.ShareDescription,
			ShareType:           finding.ShareType,
			FilePath:            finding.FilePath,
			Source:              finding.Source,
			ArchivePath:         finding.ArchivePath,
			ArchiveMemberPath:   finding.ArchiveMemberPath,
			ArchiveLocalInspect: finding.ArchiveLocalInspect,
			DatabaseFilePath:    finding.DatabaseFilePath,
			DatabaseTable:       finding.DatabaseTable,
			DatabaseColumn:      finding.DatabaseColumn,
			DatabaseRowContext:  finding.DatabaseRowContext,
			DFSNamespacePath:    finding.DFSNamespacePath,
			DFSLinkPath:         finding.DFSLinkPath,
			RuleID:              finding.RuleID,
			RuleName:            finding.RuleName,
			Severity:            finding.Severity,
			Confidence:          finding.Confidence,
			RuleConfidence:      finding.RuleConfidence,
			ConfidenceScore:     finding.ConfidenceScore,
			ConfidenceReasons:   append([]string{}, finding.ConfidenceReasons...),
			Category:            finding.Category,
			TriageClass:         finding.TriageClass,
			Actionable:          finding.Actionable,
			Correlated:          finding.Correlated,
			ConfidenceBreakdown: finding.ConfidenceBreakdown,
			SignalType:          finding.SignalType,
			MatchedText:         finding.MatchedText,
			MatchedTextRedacted: finding.MatchedTextRedacted,
			Context:             finding.Context,
			ContextRedacted:     finding.ContextRedacted,
			PotentialAccount:    finding.PotentialAccount,
			LineNumber:          finding.LineNumber,
			MatchedRuleIDs:      append([]string{}, finding.MatchedRuleIDs...),
			MatchedSignalTypes:  append([]string{}, finding.MatchedSignalTypes...),
			SupportingSignals:   append([]scanner.SupportingSignal{}, finding.SupportingSignals...),
			FromSYSVOL:          finding.FromSYSVOL,
			FromNETLOGON:        finding.FromNETLOGON,
			Tags:                append([]string{}, finding.Tags...),
			Match:               finding.Match,
			Snippet:             finding.MatchSnippet,
			MatchReason:         finding.MatchReason,
			RuleExplanation:     finding.RuleExplanation,
			RuleRemediation:     finding.RuleRemediation,
		})
	}
	if parsed.Performance != nil {
		perf := *parsed.Performance
		perf.ClassificationDistribution = append([]ClassificationSummary{}, parsed.Performance.ClassificationDistribution...)
		report.Performance = &perf
	} else {
		report.Performance = derivePerformanceSummary(parsed.Summary, report.Findings)
	}

	return report, nil
}

func derivePerformanceSummary(summary scanResultSummary, findings []scanner.Finding) *PerformanceSummary {
	duration := summary.EndedAt.Sub(summary.StartedAt)
	if summary.StartedAt.IsZero() || summary.EndedAt.IsZero() || duration < 0 {
		duration = 0
	}

	filesScanned := summary.FilesScanned
	findingsTotal := summary.MatchesFound
	if findingsTotal <= 0 {
		findingsTotal = len(findings)
	}

	filesPerSecond := 0.0
	if duration > 0 && filesScanned > 0 {
		filesPerSecond = float64(filesScanned) / duration.Seconds()
	}

	return &PerformanceSummary{
		FilesScanned:               filesScanned,
		FindingsTotal:              findingsTotal,
		DurationMS:                 duration.Milliseconds(),
		FilesPerSecond:             filesPerSecond,
		ClassificationDistribution: classificationDistribution(findings),
	}
}

func classificationDistribution(findings []scanner.Finding) []ClassificationSummary {
	if len(findings) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for _, finding := range findings {
		class := strings.ToLower(strings.TrimSpace(finding.TriageClass))
		if class == "" {
			class = "unclassified"
		}
		counts[class]++
	}
	out := make([]ClassificationSummary, 0, len(counts))
	for class, count := range counts {
		out = append(out, ClassificationSummary{Class: class, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Class < out[j].Class
		}
		return out[i].Count > out[j].Count
	})
	return out
}

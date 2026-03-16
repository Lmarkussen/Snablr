package diff

import (
	"encoding/json"
	"fmt"
	"os"

	"snablr/internal/scanner"
)

type scanResultFile struct {
	Findings []scanResultFinding `json:"findings"`
}

type scanResultFinding struct {
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
	SignalType          string                     `json:"signal_type,omitempty"`
	MatchedText         string                     `json:"matched_text,omitempty"`
	MatchedTextRedacted string                     `json:"matched_text_redacted,omitempty"`
	Context             string                     `json:"context,omitempty"`
	ContextRedacted     string                     `json:"context_redacted,omitempty"`
	PotentialAccount    string                     `json:"potential_account,omitempty"`
	LineNumber          int                        `json:"line_number,omitempty"`
	MatchedRuleIDs      []string                   `json:"matched_rule_ids,omitempty"`
	MatchedSignalTypes  []string                   `json:"matched_signal_types,omitempty"`
	SupportingSignals   []scanner.SupportingSignal `json:"supporting_signals,omitempty"`
	FromSYSVOL          bool                       `json:"from_sysvol,omitempty"`
	FromNETLOGON        bool                       `json:"from_netlogon,omitempty"`
	Tags                []string                   `json:"tags,omitempty"`
	Match               string                     `json:"match,omitempty"`
	MatchSnippet        string                     `json:"match_snippet,omitempty"`
	MatchReason         string                     `json:"match_reason,omitempty"`
	RuleExplanation     string                     `json:"rule_explanation,omitempty"`
	RuleRemediation     string                     `json:"rule_remediation,omitempty"`
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

	return report, nil
}

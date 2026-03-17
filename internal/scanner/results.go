package scanner

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"snablr/internal/rules"
)

type SupportingSignal struct {
	SignalType string `json:"signal_type"`
	RuleID     string `json:"rule_id,omitempty"`
	RuleName   string `json:"rule_name,omitempty"`
	Match      string `json:"match,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Weight     int    `json:"weight,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type ConfidenceBreakdown struct {
	BaseScore                   int    `json:"base_score,omitempty"`
	FinalScore                  int    `json:"final_score,omitempty"`
	ContentSignalStrength       int    `json:"content_signal_strength,omitempty"`
	HeuristicSignalContribution int    `json:"heuristic_signal_contribution,omitempty"`
	ValueQualityScore           int    `json:"value_quality_score,omitempty"`
	ValueQualityLabel           string `json:"value_quality_label,omitempty"`
	ValueQualityReason          string `json:"value_quality_reason,omitempty"`
	CorrelationContribution     int    `json:"correlation_contribution,omitempty"`
	PathContextContribution     int    `json:"path_context_contribution,omitempty"`
	TriageAdjustment            int    `json:"triage_adjustment,omitempty"`
}

type findingEvidence struct {
	SignalType          string
	Match               string
	MatchedText         string
	MatchedTextRedacted string
	Snippet             string
	Context             string
	ContextRedacted     string
	PotentialAccount    string
	LineNumber          int
}

type Finding struct {
	RuleID              string              `json:"rule_id"`
	RuleName            string              `json:"rule_name"`
	Severity            string              `json:"severity"`
	Confidence          string              `json:"confidence,omitempty"`
	RuleConfidence      string              `json:"rule_confidence,omitempty"`
	ConfidenceScore     int                 `json:"confidence_score,omitempty"`
	ConfidenceReasons   []string            `json:"confidence_reasons,omitempty"`
	Category            string              `json:"category"`
	TriageClass         string              `json:"triage_class,omitempty"`
	Actionable          bool                `json:"actionable,omitempty"`
	Correlated          bool                `json:"correlated,omitempty"`
	ConfidenceBreakdown ConfidenceBreakdown `json:"confidence_breakdown,omitempty"`
	Priority            int                 `json:"priority,omitempty"`
	PriorityReason      string              `json:"priority_reason,omitempty"`
	SharePriority       int                 `json:"share_priority,omitempty"`
	SharePriorityReason string              `json:"share_priority_reason,omitempty"`
	FilePath            string              `json:"file_path"`
	Share               string              `json:"share,omitempty"`
	ShareDescription    string              `json:"share_description,omitempty"`
	ShareType           string              `json:"share_type,omitempty"`
	Host                string              `json:"host,omitempty"`
	Source              string              `json:"source,omitempty"`
	DFSNamespacePath    string              `json:"dfs_namespace_path,omitempty"`
	DFSLinkPath         string              `json:"dfs_link_path,omitempty"`
	SignalType          string              `json:"signal_type,omitempty"`
	Match               string              `json:"match,omitempty"`
	MatchedText         string              `json:"matched_text,omitempty"`
	MatchedTextRedacted string              `json:"matched_text_redacted,omitempty"`
	Snippet             string              `json:"snippet,omitempty"`
	Context             string              `json:"context,omitempty"`
	ContextRedacted     string              `json:"context_redacted,omitempty"`
	PotentialAccount    string              `json:"potential_account,omitempty"`
	LineNumber          int                 `json:"line_number,omitempty"`
	MatchReason         string              `json:"match_reason,omitempty"`
	RuleExplanation     string              `json:"rule_explanation,omitempty"`
	RuleRemediation     string              `json:"rule_remediation,omitempty"`
	FromSYSVOL          bool                `json:"from_sysvol,omitempty"`
	FromNETLOGON        bool                `json:"from_netlogon,omitempty"`
	MatchedRuleIDs      []string            `json:"matched_rule_ids,omitempty"`
	MatchedSignalTypes  []string            `json:"matched_signal_types,omitempty"`
	SupportingSignals   []SupportingSignal  `json:"supporting_signals,omitempty"`
	Tags                []string            `json:"tags,omitempty"`
}

type FindingSink interface {
	WriteFinding(Finding) error
	Close() error
}

type SuppressedFinding struct {
	Host     string `json:"host,omitempty"`
	Share    string `json:"share,omitempty"`
	FilePath string `json:"file_path,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Category string `json:"category,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type ValidationObserver interface {
	RecordSuppressedFinding(SuppressedFinding)
	RecordVisibleFinding(Finding)
	RecordDowngradedFinding(Finding)
}

type ScanObserver interface {
	RecordHost(string)
	RecordShare(string, string)
	RecordFile(FileMetadata)
	RecordSkip(FileMetadata, string)
	RecordReadError(FileMetadata, error)
}

type FileMetadata struct {
	FilePath            string
	Share               string
	ShareDescription    string
	ShareType           string
	Host                string
	Source              string
	Priority            int
	PriorityReason      string
	DFSNamespacePath    string
	DFSLinkPath         string
	Size                int64
	ModifiedAt          time.Time
	IsDir               bool
	Name                string
	Extension           string
	SharePriority       int
	SharePriorityReason string
	FromSYSVOL          bool
	FromNETLOGON        bool
}

type Evaluation struct {
	Skipped     bool
	SkipReason  string
	NeedContent bool
	ContentRead bool
	Findings    []Finding
}

func (m FileMetadata) Normalized() FileMetadata {
	out := m
	out.FilePath = rules.NormalizePath(out.FilePath)
	if out.Name == "" {
		out.Name = filepath.Base(out.FilePath)
	}
	if out.Extension == "" {
		out.Extension = filepath.Ext(out.Name)
	}
	return out
}

func newFinding(rule rules.Rule, meta FileMetadata, evidence findingEvidence) Finding {
	tags := append([]string{}, rule.Tags...)
	if meta.FromSYSVOL {
		tags = append(tags, "ad-share:sysvol")
	}
	if meta.FromNETLOGON {
		tags = append(tags, "ad-share:netlogon")
	}
	if strings.Contains(strings.ToLower(meta.Source), "dfs") {
		tags = append(tags, "source:dfs")
	}

	signalType := signalTypeForRule(rule.Type)
	if strings.TrimSpace(evidence.SignalType) != "" {
		signalType = strings.TrimSpace(evidence.SignalType)
	}
	signal := SupportingSignal{
		SignalType: signalType,
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		Match:      evidence.Match,
		Confidence: strings.TrimSpace(string(rule.Confidence)),
		Weight:     baseSignalWeight(signalType),
		Reason:     signalReasonForRule(rule, evidence.Match),
	}

	finding := Finding{
		RuleID:              rule.ID,
		RuleName:            rule.Name,
		Severity:            string(rule.Severity),
		Confidence:          string(rule.Confidence),
		RuleConfidence:      string(rule.Confidence),
		Category:            rule.Category,
		Priority:            meta.Priority,
		PriorityReason:      meta.PriorityReason,
		SharePriority:       meta.SharePriority,
		SharePriorityReason: meta.SharePriorityReason,
		FilePath:            meta.FilePath,
		Share:               meta.Share,
		ShareDescription:    meta.ShareDescription,
		ShareType:           meta.ShareType,
		Host:                meta.Host,
		Source:              meta.Source,
		DFSNamespacePath:    meta.DFSNamespacePath,
		DFSLinkPath:         meta.DFSLinkPath,
		SignalType:          signalType,
		Match:               evidence.Match,
		MatchedText:         evidence.MatchedText,
		MatchedTextRedacted: evidence.MatchedTextRedacted,
		Snippet:             evidence.Snippet,
		Context:             evidence.Context,
		ContextRedacted:     evidence.ContextRedacted,
		PotentialAccount:    evidence.PotentialAccount,
		LineNumber:          evidence.LineNumber,
		MatchReason:         matchReason(rule, evidence.Match, meta),
		RuleExplanation:     strings.TrimSpace(rule.Explanation),
		RuleRemediation:     strings.TrimSpace(rule.Remediation),
		FromSYSVOL:          meta.FromSYSVOL,
		FromNETLOGON:        meta.FromNETLOGON,
		MatchedRuleIDs:      []string{rule.ID},
		MatchedSignalTypes:  []string{signalType},
		SupportingSignals:   []SupportingSignal{signal},
		Tags:                tags,
	}
	return applyTriageMetadata(finding)
}

func matchReason(rule rules.Rule, match string, meta FileMetadata) string {
	surface := "file metadata"
	context := "matched the configured rule"

	switch rule.Type {
	case rules.RuleTypeContent:
		surface = "file contents"
		context = "contained text that matches the rule"
	case rules.RuleTypeFilename:
		surface = "filename"
		context = "matched a heuristic naming pattern covered by the rule"
	case rules.RuleTypeExtension:
		surface = "file extension"
		context = "matched an extension-based heuristic covered by the rule"
	}

	reason := strings.TrimSpace(rule.Description)
	if reason == "" {
		reason = rule.Name
	}

	match = strings.TrimSpace(match)
	if len(match) > 80 {
		match = match[:77] + "..."
	}

	if match == "" {
		return surface + " " + context + " for " + reason + "."
	}

	return surface + " " + context + ` with match "` + match + `" for ` + reason + "."
}

func heuristicEvidence(ruleType rules.RuleType, match string) findingEvidence {
	signalType := signalTypeForRule(ruleType)
	return findingEvidence{
		SignalType:          signalType,
		Match:               match,
		MatchedText:         match,
		MatchedTextRedacted: match,
	}
}

func signalTypeForRule(ruleType rules.RuleType) string {
	switch ruleType {
	case rules.RuleTypeContent:
		return "content"
	case rules.RuleTypeExtension:
		return "extension"
	case rules.RuleTypeFilename:
		return "filename"
	default:
		return "metadata"
	}
}

func signalReasonForRule(rule rules.Rule, match string) string {
	match = strings.TrimSpace(match)
	reason := strings.TrimSpace(rule.Description)
	if reason == "" {
		reason = strings.TrimSpace(rule.Name)
	}
	switch rule.Type {
	case rules.RuleTypeContent:
		if match != "" {
			return `content rule matched "` + match + `" for ` + reason
		}
		return "content rule matched for " + reason
	case rules.RuleTypeExtension:
		if match != "" {
			return `extension rule matched "` + match + `" for ` + reason
		}
		return "extension rule matched for " + reason
	default:
		if match != "" {
			return `filename rule matched "` + match + `" for ` + reason
		}
		return "filename rule matched for " + reason
	}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]string, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = trimmed
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

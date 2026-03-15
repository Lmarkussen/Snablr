package scanner

import (
	"path/filepath"
	"strings"

	"snablr/internal/rules"
)

type Finding struct {
	RuleID           string   `json:"rule_id"`
	RuleName         string   `json:"rule_name"`
	Severity         string   `json:"severity"`
	Confidence       string   `json:"confidence,omitempty"`
	Category         string   `json:"category"`
	Priority         int      `json:"priority,omitempty"`
	PriorityReason   string   `json:"priority_reason,omitempty"`
	FilePath         string   `json:"file_path"`
	Share            string   `json:"share,omitempty"`
	ShareDescription string   `json:"share_description,omitempty"`
	ShareType        string   `json:"share_type,omitempty"`
	Host             string   `json:"host,omitempty"`
	Source           string   `json:"source,omitempty"`
	DFSNamespacePath string   `json:"dfs_namespace_path,omitempty"`
	DFSLinkPath      string   `json:"dfs_link_path,omitempty"`
	Match            string   `json:"match,omitempty"`
	Snippet          string   `json:"snippet,omitempty"`
	MatchReason      string   `json:"match_reason,omitempty"`
	RuleExplanation  string   `json:"rule_explanation,omitempty"`
	RuleRemediation  string   `json:"rule_remediation,omitempty"`
	FromSYSVOL       bool     `json:"from_sysvol,omitempty"`
	FromNETLOGON     bool     `json:"from_netlogon,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type FindingSink interface {
	WriteFinding(Finding) error
	Close() error
}

type ScanObserver interface {
	RecordHost(string)
	RecordShare(string, string)
	RecordFile(FileMetadata)
	RecordSkip(FileMetadata, string)
	RecordReadError(FileMetadata, error)
}

type FileMetadata struct {
	FilePath         string
	Share            string
	ShareDescription string
	ShareType        string
	Host             string
	Source           string
	Priority         int
	PriorityReason   string
	DFSNamespacePath string
	DFSLinkPath      string
	Size             int64
	IsDir            bool
	Name             string
	Extension        string
	FromSYSVOL       bool
	FromNETLOGON     bool
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

func newFinding(rule rules.Rule, meta FileMetadata, match string, snippet string) Finding {
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

	return Finding{
		RuleID:           rule.ID,
		RuleName:         rule.Name,
		Severity:         string(rule.Severity),
		Confidence:       string(rule.Confidence),
		Category:         rule.Category,
		Priority:         meta.Priority,
		PriorityReason:   meta.PriorityReason,
		FilePath:         meta.FilePath,
		Share:            meta.Share,
		ShareDescription: meta.ShareDescription,
		ShareType:        meta.ShareType,
		Host:             meta.Host,
		Source:           meta.Source,
		DFSNamespacePath: meta.DFSNamespacePath,
		DFSLinkPath:      meta.DFSLinkPath,
		Match:            match,
		Snippet:          snippet,
		MatchReason:      matchReason(rule, match, meta),
		RuleExplanation:  strings.TrimSpace(rule.Explanation),
		RuleRemediation:  strings.TrimSpace(rule.Remediation),
		FromSYSVOL:       meta.FromSYSVOL,
		FromNETLOGON:     meta.FromNETLOGON,
		Tags:             tags,
	}
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
		context = "contains a keyword or naming pattern covered by the rule"
	case rules.RuleTypeExtension:
		surface = "file extension"
		context = "uses an extension prioritized by the rule"
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

package rules

import (
	"path/filepath"
	"regexp"
	"strings"
)

type RuleFile struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Rules       []Rule `yaml:"rules"`

	SourceFile string `yaml:"-"`
}

type Rule struct {
	ID             string     `yaml:"id"`
	Name           string     `yaml:"name"`
	Description    string     `yaml:"description"`
	Type           RuleType   `yaml:"type"`
	Pattern        string     `yaml:"pattern"`
	CaseSensitive  bool       `yaml:"case_sensitive"`
	Severity       Severity   `yaml:"severity"`
	Confidence     Confidence `yaml:"confidence"`
	Explanation    string     `yaml:"explanation"`
	Remediation    string     `yaml:"remediation"`
	Tags           []string   `yaml:"tags"`
	Category       string     `yaml:"category"`
	Enabled        bool       `yaml:"enabled"`
	IncludePaths   []string   `yaml:"include_paths"`
	ExcludePaths   []string   `yaml:"exclude_paths"`
	FileExtensions []string   `yaml:"file_extensions"`
	MaxFileSize    int64      `yaml:"max_file_size"`
	Action         RuleAction `yaml:"action"`

	SourceFile string   `yaml:"-"`
	FileName   string   `yaml:"-"`
	index      int      `yaml:"-"`
	unknown    []string `yaml:"-"`

	compiled *regexp.Regexp
}

type RuleType string

const (
	RuleTypeContent   RuleType = "content"
	RuleTypeFilename  RuleType = "filename"
	RuleTypeExtension RuleType = "extension"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type RuleAction string

const (
	ActionReport     RuleAction = "report"
	ActionSkip       RuleAction = "skip"
	ActionPrioritize RuleAction = "prioritize"
)

type Candidate struct {
	Path      string
	Name      string
	Extension string
	Content   string
	Size      int64
	IsDir     bool
}

type MatchResult struct {
	Rule    Rule
	Matched []string
}

func NormalizePath(path string) string {
	clean := filepath.Clean(path)
	return filepath.ToSlash(clean)
}

func normalizeExtension(ext string) string {
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.ToLower(ext)
}

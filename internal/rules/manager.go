package rules

import (
	"path/filepath"
	"strings"
	"sync"
)

type ManagerOptions struct {
	EnabledRuleIDs  []string
	DisabledRuleIDs []string
	IncludeTags     []string
	ExcludeTags     []string
	MinSeverity     Severity
}

type Manager struct {
	mu sync.RWMutex

	paths []string
	opts  ManagerOptions

	files        []RuleFile
	allRules     []Rule
	enabledRules []Rule
	issues       []ValidationIssue

	contentRules   []Rule
	filenameRules  []Rule
	extensionRules []Rule
	skipRules      []Rule
}

func (m *Manager) Reload() ([]ValidationIssue, error) {
	files, loadIssues, err := LoadRuleFiles(m.paths)
	if err != nil {
		return nil, err
	}

	validRules, validationIssues := ValidateRuleFiles(files)
	issues := append(loadIssues, validationIssues...)
	enabledRules := filterEnabledRules(validRules, m.opts)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.files = files
	m.allRules = validRules
	m.enabledRules = enabledRules
	m.issues = issues
	m.contentRules = nil
	m.filenameRules = nil
	m.extensionRules = nil
	m.skipRules = nil

	for _, rule := range enabledRules {
		switch rule.Type {
		case RuleTypeContent:
			m.contentRules = append(m.contentRules, rule)
		case RuleTypeFilename:
			m.filenameRules = append(m.filenameRules, rule)
		case RuleTypeExtension:
			m.extensionRules = append(m.extensionRules, rule)
		}

		if rule.Action == ActionSkip {
			m.skipRules = append(m.skipRules, rule)
		}
	}

	return cloneIssues(issues), nil
}

func (m *Manager) Validate() []ValidationIssue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneIssues(m.issues)
}

func (m *Manager) RuleFiles() []RuleFile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]RuleFile, len(m.files))
	copy(out, m.files)
	return out
}

func (m *Manager) Rules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Rule, len(m.allRules))
	copy(out, m.allRules)
	return out
}

func (m *Manager) EnabledRules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Rule, len(m.enabledRules))
	copy(out, m.enabledRules)
	return out
}

func (m *Manager) RulesByType(ruleType RuleType) []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var source []Rule
	switch ruleType {
	case RuleTypeContent:
		source = m.contentRules
	case RuleTypeFilename:
		source = m.filenameRules
	case RuleTypeExtension:
		source = m.extensionRules
	}

	out := make([]Rule, len(source))
	copy(out, source)
	return out
}

func (m *Manager) ShouldExclude(candidate Candidate) (bool, *Rule) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, rule := range m.skipRules {
		if !ruleEligible(rule, candidate) {
			continue
		}
		if matched, _ := matchRule(rule, candidate); matched {
			copyRule := rule
			return true, &copyRule
		}
	}
	return false, nil
}

func (m *Manager) MatchFilename(candidate Candidate) []MatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]MatchResult, 0)
	results = append(results, collectMatches(m.filenameRules, candidate)...)
	results = append(results, collectMatches(m.extensionRules, candidate)...)
	return results
}

func (m *Manager) MatchContent(candidate Candidate) []MatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return collectMatches(m.contentRules, candidate)
}

func collectMatches(ruleSet []Rule, candidate Candidate) []MatchResult {
	results := make([]MatchResult, 0)
	for _, rule := range ruleSet {
		if rule.Action == ActionSkip {
			continue
		}
		if !ruleEligible(rule, candidate) {
			continue
		}
		if matched, values := matchRule(rule, candidate); matched {
			results = append(results, MatchResult{
				Rule:    rule,
				Matched: values,
			})
		}
	}
	return results
}

func filterEnabledRules(rules []Rule, opts ManagerOptions) []Rule {
	filtered := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if containsString(opts.DisabledRuleIDs, rule.ID) {
			continue
		}
		if !rule.Enabled && !containsString(opts.EnabledRuleIDs, rule.ID) {
			continue
		}
		if !tagsAllowed(rule.Tags, opts.IncludeTags, opts.ExcludeTags) {
			continue
		}
		if !meetsMinSeverity(rule, opts.MinSeverity) {
			continue
		}
		filtered = append(filtered, normalizeRule(rule))
	}
	return filtered
}

func tagsAllowed(ruleTags, includeTags, excludeTags []string) bool {
	if intersects(ruleTags, excludeTags) {
		return false
	}
	if len(includeTags) == 0 {
		return true
	}
	return intersects(ruleTags, includeTags)
}

func meetsMinSeverity(rule Rule, min Severity) bool {
	if min == "" || rule.Action == ActionSkip {
		return true
	}
	return severityRank(rule.Severity) >= severityRank(min)
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return -1
	}
}

func normalizeRule(rule Rule) Rule {
	rule.SourceFile = filepath.Clean(rule.SourceFile)
	for i, ext := range rule.FileExtensions {
		rule.FileExtensions[i] = normalizeExtension(ext)
	}
	return rule
}

func ruleEligible(rule Rule, candidate Candidate) bool {
	if rule.MaxFileSize > 0 && candidate.Size > rule.MaxFileSize {
		return false
	}
	if len(rule.FileExtensions) > 0 && !matchExtensionList(candidate.Extension, rule.FileExtensions) {
		return false
	}
	if len(rule.IncludePaths) > 0 && !containsAny(candidate.Path, rule.IncludePaths) {
		return false
	}
	if len(rule.ExcludePaths) > 0 && containsAny(candidate.Path, rule.ExcludePaths) {
		return false
	}
	if rule.Type == RuleTypeContent && candidate.IsDir {
		return false
	}
	return true
}

func matchRule(rule Rule, candidate Candidate) (bool, []string) {
	input := candidateValue(rule.Type, candidate)
	if input == "" {
		return false, nil
	}
	if rule.compiled == nil {
		return false, nil
	}

	found := rule.compiled.FindAllString(input, 5)
	if len(found) == 0 {
		return false, nil
	}
	return true, found
}

func candidateValue(ruleType RuleType, candidate Candidate) string {
	switch ruleType {
	case RuleTypeContent:
		return candidate.Content
	case RuleTypeFilename:
		return candidate.Name
	case RuleTypeExtension:
		return normalizeExtension(candidate.Extension)
	default:
		return ""
	}
}

func matchExtensionList(candidateExt string, ruleExts []string) bool {
	normalized := normalizeExtension(candidateExt)
	for _, ext := range ruleExts {
		if normalized == normalizeExtension(ext) {
			return true
		}
	}
	return false
}

func containsAny(value string, patterns []string) bool {
	value = strings.ToLower(NormalizePath(value))
	for _, pattern := range patterns {
		if strings.Contains(value, strings.ToLower(filepath.ToSlash(pattern))) {
			return true
		}
	}
	return false
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func intersects(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if strings.EqualFold(l, r) {
				return true
			}
		}
	}
	return false
}

func cloneIssues(issues []ValidationIssue) []ValidationIssue {
	out := make([]ValidationIssue, len(issues))
	copy(out, issues)
	return out
}

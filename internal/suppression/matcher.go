package suppression

import (
	"fmt"
	"slices"
	"strings"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/scanner"
)

type Match struct {
	SuppressionID          string
	SuppressionDescription string
	SuppressionReason      string
	Fingerprint            string
}

type Matcher struct {
	rules []compiledRule
}

type compiledRule struct {
	id          string
	description string
	reason      string
	hosts       []string
	shares      []string
	ruleIDs     []string
	categories  []string
	exactPaths  []string
	prefixes    []string
	contains    []string
	fingerprints []string
	tags        []string
}

func New(rules []config.SuppressionRule) *Matcher {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		compiled = append(compiled, compiledRule{
			id:           strings.TrimSpace(rule.ID),
			description:  strings.TrimSpace(rule.Description),
			reason:       strings.TrimSpace(rule.Reason),
			hosts:        normalizeValues(rule.Hosts),
			shares:       normalizeValues(rule.Shares),
			ruleIDs:      normalizeValues(rule.RuleIDs),
			categories:   normalizeValues(rule.Categories),
			exactPaths:   normalizePaths(rule.ExactPaths),
			prefixes:     normalizePaths(rule.PathPrefixes),
			contains:     normalizePaths(rule.PathContains),
			fingerprints: normalizeValues(rule.Fingerprints),
			tags:         normalizeValues(rule.Tags),
		})
	}
	if len(compiled) == 0 {
		return nil
	}
	return &Matcher{rules: compiled}
}

func (m *Matcher) Match(f scanner.Finding) (Match, bool) {
	if m == nil || len(m.rules) == 0 {
		return Match{}, false
	}
	normalizedPath := normalizePath(f.FilePath)
	fingerprint := FingerprintString(f)
	host := normalizeValue(f.Host)
	share := normalizeValue(f.Share)
	category := normalizeValue(f.Category)
	ruleIDs := normalizeValues(append([]string{f.RuleID}, f.MatchedRuleIDs...))
	tags := normalizeValues(f.Tags)

	for _, rule := range m.rules {
		if !matchAny(rule.hosts, host) {
			continue
		}
		if !matchAny(rule.shares, share) {
			continue
		}
		if !matchSlice(rule.ruleIDs, ruleIDs) {
			continue
		}
		if !matchAny(rule.categories, category) {
			continue
		}
		if !matchAny(rule.fingerprints, fingerprint) {
			continue
		}
		if !matchAny(rule.exactPaths, normalizedPath) {
			continue
		}
		if !matchPrefix(rule.prefixes, normalizedPath) {
			continue
		}
		if !matchContains(rule.contains, normalizedPath) {
			continue
		}
		if !matchSlice(rule.tags, tags) {
			continue
		}
		return Match{
			SuppressionID:          rule.id,
			SuppressionDescription: rule.description,
			SuppressionReason:      rule.reason,
			Fingerprint:            fingerprint,
		}, true
	}
	return Match{}, false
}

func FingerprintString(f scanner.Finding) string {
	fp := diff.Fingerprint(f)
	return fmt.Sprintf("%s|%s|%s|%s|%s", fp.RuleID, fp.Host, fp.Share, fp.FilePath, fp.Match)
}

func normalizeValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeValue(value); normalized != "" {
			out = append(out, normalized)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func normalizePaths(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizePath(value); normalized != "" {
			out = append(out, normalized)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\`, `/`)
	return strings.ToLower(value)
}

func matchAny(want []string, got string) bool {
	if len(want) == 0 {
		return true
	}
	return slices.Contains(want, got)
}

func matchSlice(want, got []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, item := range got {
		if slices.Contains(want, item) {
			return true
		}
	}
	return false
}

func matchPrefix(prefixes []string, got string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(got, prefix) {
			return true
		}
	}
	return false
}

func matchContains(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.Contains(got, value) {
			return true
		}
	}
	return false
}

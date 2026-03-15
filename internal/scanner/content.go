package scanner

import (
	"bytes"
	"strings"

	"snablr/internal/rules"
)

type ContentScanner struct {
	snippetBytes int
}

func NewContentScanner(snippetBytes int) ContentScanner {
	if snippetBytes <= 0 {
		snippetBytes = 120
	}
	return ContentScanner{snippetBytes: snippetBytes}
}

func (s ContentScanner) NeedsContent(ruleSet []rules.Rule, meta FileMetadata) bool {
	if meta.IsDir {
		return false
	}
	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if ruleMatchesMetadata(rule, meta) {
			return true
		}
	}
	return false
}

func (s ContentScanner) Scan(ruleSet []rules.Rule, meta FileMetadata, content []byte) []Finding {
	findings := make([]Finding, 0)
	if len(content) == 0 {
		return findings
	}

	contentString := string(content)
	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if !ruleMatchesMetadata(rule, meta) {
			continue
		}

		match, ok := firstMatch(rule, contentString)
		if !ok {
			continue
		}

		snippet := makeSnippet(content, match, s.snippetBytes, rule.CaseSensitive)
		findings = append(findings, newFinding(rule, meta, match, snippet))
	}
	return findings
}

func makeSnippet(content []byte, match string, snippetBytes int, caseSensitive bool) string {
	if len(content) == 0 || match == "" {
		return ""
	}

	haystack := content
	needle := []byte(match)
	if !caseSensitive {
		haystack = bytes.ToLower(content)
		needle = bytes.ToLower(needle)
	}

	index := bytes.Index(haystack, needle)
	if index < 0 {
		return truncateSnippet(string(content), snippetBytes)
	}

	start := index - (snippetBytes / 2)
	if start < 0 {
		start = 0
	}
	end := start + snippetBytes
	if end > len(content) {
		end = len(content)
	}

	snippet := strings.ReplaceAll(string(content[start:end]), "\n", "\\n")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	return snippet
}

func truncateSnippet(content string, max int) string {
	if max <= 0 || len(content) <= max {
		return content
	}
	content = strings.ReplaceAll(content[:max], "\n", "\\n")
	content = strings.ReplaceAll(content, "\r", "")
	return content
}

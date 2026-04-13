package scanner

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"snablr/internal/rules"
)

type ContentScanner struct {
	snippetBytes   int
	validationMode bool
	observer       ValidationObserver
	log            validationLogger
}

type validationLogger interface {
	Infof(string, ...any)
}

type contentMatchDetails struct {
	match               string
	matchedText         string
	matchedTextRedacted string
	snippet             string
	context             string
	contextRedacted     string
	potentialAccount    string
	lineNumber          int
}

var (
	assignmentSecretRegex = regexp.MustCompile(`(?i)\b(password|passord|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|connection\s*string|conn(?:ection)?[_-]?string)\b(\s*[:=]\s*)(["']?)([^"'\r\n;]+)(?:["']?)`)
	xmlSecretRegex        = regexp.MustCompile(`(?i)<(password|passord|passwd|pwd|secret|token|apikey|clientsecret)>([^<]+)</[^>]+>`)
	identityLineRegex     = regexp.MustCompile(`(?i)\b(user(name)?|login|account|email|upn|domain|domene|domain administrator|domene administrator)\b`)
	genericPairRegex      = regexp.MustCompile(`(?im)^\s*((?:[A-Za-z][A-Za-z0-9._@-]{1,32})|(?:domain administrator)|(?:domene administrator))(\s*[:=]\s*)([^\s"';]{4,64})\s*$`)
)

var disallowedGenericPairLabels = map[string]struct{}{
	"http":  {},
	"https": {},
	"ftp":   {},
	"ftps":  {},
	"smb":   {},
	"ldap":  {},
	"ldaps": {},
	"ssh":   {},
	"file":  {},
}

type genericPairMatch struct {
	Label string
	Sep   string
	Value string
}

func NewContentScanner(snippetBytes int, validationMode bool, observer ValidationObserver, log validationLogger) ContentScanner {
	if snippetBytes <= 0 {
		snippetBytes = 120
	}
	return ContentScanner{
		snippetBytes:   snippetBytes,
		validationMode: validationMode,
		observer:       observer,
		log:            log,
	}
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

	contentString := strings.TrimPrefix(string(content), "\uFEFF")
	contentString = strings.ReplaceAll(contentString, "\r\n", "\n")
	contentString = strings.ReplaceAll(contentString, "\r", "\n")
	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if !ruleMatchesMetadata(rule, meta) {
			continue
		}

		details, ok := buildContentMatchDetails(rule, contentString, s.snippetBytes)
		if !ok {
			continue
		}
		if suppress, reason := weakContentSuppression(rule.ID, rule.Category, details.matchedText, details.context); suppress {
			if s.observer != nil {
				s.observer.RecordSuppressedFinding(SuppressedFinding{
					Host:     meta.Host,
					Share:    meta.Share,
					FilePath: meta.FilePath,
					RuleID:   rule.ID,
					Category: rule.Category,
					Reason:   reason,
				})
			}
			if s.validationMode && s.log != nil {
				s.log.Infof("validation: suppressed finding for %s rule=%s reason=%s", meta.FilePath, rule.ID, reason)
			}
			continue
		}

		findings = append(findings, newFinding(rule, meta, findingEvidence{
			SignalType:          signalTypeForRule(rule.Type),
			Match:               details.match,
			MatchedText:         details.matchedText,
			MatchedTextRedacted: details.matchedTextRedacted,
			Snippet:             details.snippet,
			Context:             details.context,
			ContextRedacted:     details.contextRedacted,
			PotentialAccount:    details.potentialAccount,
			LineNumber:          details.lineNumber,
		}))
	}
	return findings
}

func buildContentMatchDetails(rule rules.Rule, content string, snippetBytes int) (contentMatchDetails, bool) {
	rx, err := compiledPattern(rule)
	if err != nil {
		return contentMatchDetails{}, false
	}

	matchRange := rx.FindStringIndex(content)
	if len(matchRange) != 2 {
		return contentMatchDetails{}, false
	}

	match := content[matchRange[0]:matchRange[1]]
	if rule.ID == "content.note_style_credential_pair_indicators" {
		if _, ok := parseGenericPairLine(match); !ok {
			return contentMatchDetails{}, false
		}
	}
	context, lineNumber, potentialAccount := captureMatchContext(content, matchRange[0], matchRange[1])
	redactedMatch := redactSensitiveText(match)
	redactedContext := redactSensitiveText(context)

	return contentMatchDetails{
		match:               match,
		matchedText:         match,
		matchedTextRedacted: redactedMatch,
		snippet:             flattenSnippet(context, snippetBytes),
		context:             limitRunes(context, 320),
		contextRedacted:     limitRunes(redactedContext, 320),
		potentialAccount:    limitRunes(potentialAccount, 160),
		lineNumber:          lineNumber,
	}, true
}

func captureMatchContext(content string, start, end int) (string, int, string) {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	start = clampIndex(normalizedIndex(content, start), len(normalized))
	end = clampIndex(normalizedIndex(content, end), len(normalized))

	lines := strings.Split(normalized, "\n")
	lineIndex := strings.Count(normalized[:start], "\n")
	if lineIndex < 0 {
		lineIndex = 0
	}
	if lineIndex >= len(lines) {
		lineIndex = len(lines) - 1
	}

	contextStart := max(0, lineIndex-1)
	contextEnd := min(len(lines), lineIndex+2)
	context := strings.TrimSpace(strings.Join(lines[contextStart:contextEnd], "\n"))
	if context == "" && lineIndex >= 0 && lineIndex < len(lines) {
		context = strings.TrimSpace(lines[lineIndex])
	}

	return context, lineIndex + 1, nearbyIdentityLine(lines, lineIndex)
}

func normalizedIndex(content string, idx int) int {
	idx = clampIndex(idx, len(content))
	return len(strings.ReplaceAll(content[:idx], "\r", ""))
}

func flattenSnippet(content string, maxBytes int) string {
	content = strings.ReplaceAll(content, "\n", `\n`)
	content = strings.ReplaceAll(content, "\r", "")
	return limitRunes(content, maxBytes)
}

func nearbyIdentityLine(lines []string, lineIndex int) string {
	if len(lines) == 0 {
		return ""
	}

	check := func(idx int) string {
		if idx < 0 || idx >= len(lines) {
			return ""
		}
		line := strings.TrimSpace(lines[idx])
		if line == "" {
			return ""
		}
		if match, ok := parseGenericPairLine(line); ok {
			return match.Label
		}
		if !identityLineRegex.MatchString(line) {
			return ""
		}
		return line
	}

	if line := check(lineIndex); line != "" {
		return line
	}
	for offset := 1; offset <= 3; offset++ {
		if line := check(lineIndex - offset); line != "" {
			return line
		}
		if line := check(lineIndex + offset); line != "" {
			return line
		}
	}
	return ""
}

func redactSensitiveText(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}

	redacted := assignmentSecretRegex.ReplaceAllString(text, `${1}${2}${3}********`)
	redacted = xmlSecretRegex.ReplaceAllString(redacted, `<${1}>********</${1}>`)
	redacted = redactGenericPairLines(redacted)
	return redacted
}

func parseGenericPairLine(line string) (genericPairMatch, bool) {
	matches := genericPairRegex.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 4 {
		return genericPairMatch{}, false
	}

	label := strings.TrimSpace(matches[1])
	value := strings.TrimSpace(matches[3])
	if genericPairLooksLikeURI(label, value) {
		return genericPairMatch{}, false
	}

	return genericPairMatch{
		Label: label,
		Sep:   matches[2],
		Value: value,
	}, true
}

func genericPairLooksLikeURI(label, value string) bool {
	if _, blocked := disallowedGenericPairLabels[strings.ToLower(strings.TrimSpace(label))]; blocked {
		return strings.HasPrefix(strings.TrimSpace(value), "//")
	}
	return false
}

func redactGenericPairLines(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		match, ok := parseGenericPairLine(line)
		if !ok {
			continue
		}
		lines[i] = match.Label + match.Sep + "********"
	}
	return strings.Join(lines, "\n")
}

func limitRunes(value string, maxCount int) string {
	if maxCount <= 0 {
		return value
	}
	if utf8.RuneCountInString(value) <= maxCount {
		return value
	}

	runes := []rune(value)
	return string(runes[:maxCount]) + "..."
}

func clampIndex(value, maxValue int) int {
	switch {
	case value < 0:
		return 0
	case value > maxValue:
		return maxValue
	default:
		return value
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

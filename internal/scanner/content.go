package scanner

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"snablr/internal/rules"
	"snablr/internal/textdecode"
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
	xmlAddValueRegex      = regexp.MustCompile(`(?i)<add\b[^>]*\b(?:key|name)\s*=\s*["']([^"']{1,64})["'][^>]*\bvalue\s*=\s*["']([^"']+)["'][^>]*\/?>`)
	xmlSecretAttrRegex    = regexp.MustCompile(`(?i)<[^>]+\b(password|passord|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret)\s*=\s*["']([^"']+)["'][^>]*\/?>`)
	identityLineRegex     = regexp.MustCompile(`(?i)\b(user(name)?|login|account|email|upn|domain|domene|domain administrator|domene administrator)\b`)
	genericPairRegex      = regexp.MustCompile(`(?im)^\s*((?:[A-Za-z][A-Za-z0-9._@-]{1,32})|(?:domain administrator)|(?:domene administrator))(\s*[:=]\s*)([^\s"';]{4,64})\s*$`)
	credentialContextLabelRegex = regexp.MustCompile(`(?i)^(user(name)?|login|account|email|upn|admin(istrator)?|domain administrator|domene administrator|db[_-]?user|service[_-]?account)$`)
	accountAliasLabelRegex      = regexp.MustCompile(`(?i)^(svc[_-]?[a-z0-9._-]+|app[_-]?[a-z0-9._-]+|sql[_-]?[a-z0-9._-]+|adm[_-]?[a-z0-9._-]+|[a-z0-9._-]*admin)$`)
	genericResourceLabelRegex   = regexp.MustCompile(`(?i)^(msg|message|text|label|caption|title|description|desc|prompt|error|info|hint|notice|status|default(server|host|url)?|server|host|url|uri|path|dir|directory|file|folder)[0-9._-]*$`)
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

	contentString := textdecode.Normalize(content)
	if contentString == "" {
		return findings
	}
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

	matchRange := contentMatchRange(rule.ID, rx, content)
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

func contentMatchRange(ruleID string, rx *regexp.Regexp, content string) []int {
	if rx != nil {
		if ruleID == "content.note_style_credential_pair_indicators" {
			for _, matchRange := range rx.FindAllStringIndex(content, -1) {
				if len(matchRange) != 2 {
					continue
				}
				if _, ok := parseGenericPairLine(content[matchRange[0]:matchRange[1]]); ok {
					return matchRange
				}
			}
		} else if matchRange := rx.FindStringIndex(content); len(matchRange) == 2 {
			return matchRange
		}
	}

	switch ruleID {
	case "content.password_assignment_indicators":
		return xmlAssignmentRange(content, isPasswordLabel)
	case "content.secret_assignment_indicators":
		return xmlAssignmentRange(content, isSecretLabel)
	default:
		return nil
	}
}

func xmlAssignmentRange(content string, allowLabel func(string) bool) []int {
	for _, match := range xmlAddValueRegex.FindAllStringSubmatchIndex(content, -1) {
		if len(match) < 6 {
			continue
		}
		label := strings.TrimSpace(content[match[2]:match[3]])
		if !allowLabel(label) {
			continue
		}
		return []int{match[0], match[1]}
	}

	for _, match := range xmlSecretAttrRegex.FindAllStringSubmatchIndex(content, -1) {
		if len(match) < 6 {
			continue
		}
		label := strings.TrimSpace(content[match[2]:match[3]])
		if !allowLabel(label) {
			continue
		}
		return []int{match[0], match[1]}
	}

	return nil
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
		if label, value, ok := parseXMLAddValueLine(line); ok && isCredentialContextLabel(label) {
			if strings.TrimSpace(value) != "" {
				return label + "=" + value
			}
			return label
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
	redacted = redactXMLAttributeAssignments(redacted)
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
	if genericResourceLabelRegex.MatchString(strings.ToLower(label)) {
		return genericPairMatch{}, false
	}
	if !isCredentialContextLabel(label) {
		if !accountAliasLabelRegex.MatchString(label) || assessSensitiveValueQuality(value).Weak {
			return genericPairMatch{}, false
		}
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

func parseXMLAddValueLine(line string) (string, string, bool) {
	matches := xmlAddValueRegex.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 3 {
		return "", "", false
	}
	return strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2]), true
}

func redactXMLAttributeAssignments(text string) string {
	text = xmlAddValueRegex.ReplaceAllStringFunc(text, func(value string) string {
		matches := xmlAddValueRegex.FindStringSubmatch(value)
		if len(matches) != 3 {
			return value
		}
		label := strings.TrimSpace(matches[1])
		if !isSecretLabel(label) {
			return value
		}
		return strings.Replace(value, matches[2], "********", 1)
	})
	text = xmlSecretAttrRegex.ReplaceAllStringFunc(text, func(value string) string {
		matches := xmlSecretAttrRegex.FindStringSubmatch(value)
		if len(matches) != 3 {
			return value
		}
		return strings.Replace(value, matches[2], "********", 1)
	})
	return text
}

func isPasswordLabel(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "password", "passord", "passwd", "pwd", "databasepassword":
		return true
	default:
		return false
	}
}

func isSecretLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	return isPasswordLabel(label) ||
		label == "secret" ||
		label == "token" ||
		label == "apikey" ||
		label == "api_key" ||
		label == "accesskey" ||
		label == "access_key" ||
		label == "secretkey" ||
		label == "secret_key" ||
		label == "clientsecret" ||
		label == "client_secret"
}

func isCredentialContextLabel(label string) bool {
	label = strings.TrimSpace(label)
	if label == "" {
		return false
	}
	return credentialContextLabelRegex.MatchString(label)
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

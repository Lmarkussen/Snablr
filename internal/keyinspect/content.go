package keyinspect

import (
	"bytes"
	"strings"

	"snablr/internal/textdecode"
)

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	if len(content) == 0 {
		return nil
	}

	header := matchedHeader(content)
	if header == "" {
		return nil
	}
	format, algorithm, status, reviewReason, encrypted := parsePrivateKey(content, header)

	text := textdecode.Normalize(content)
	if text == "" {
		text = string(content)
	}
	lineNumber := lineForHeader(text, header)
	snippet := header
	context := limitText(text, 320)

	validationBasis := "validated_private_key_header"
	match := Match{
		ID:                  "keyinspect.content.private_key_header",
		Name:                "Validated Private Key Header",
		Description:         "Validated private key material was identified from an exact high-value private key artifact filename and a real private key header.",
		RuleType:            "content",
		SignalType:          "validated",
		Severity:            "critical",
		Confidence:          "high",
		Category:            "crypto",
		Match:               header,
		MatchedText:         header,
		MatchedTextRedacted: header,
		Snippet:             snippet,
		Context:             context,
		ContextRedacted:     context,
		LineNumber:          lineNumber,
		Explanation:         "This finding is promoted only when an exact private key artifact filename also contains a real OpenSSH or PEM private key header.",
		Remediation:         "Restrict access immediately, remove unnecessary private keys from shared storage, and rotate or replace exposed key material.",
		Tags: []string{
			"crypto",
			"keys",
			"remote-access",
			"artifact:private-key",
			"validated:private-key-header",
		},
		Format:          format,
		Algorithm:       algorithm,
		Status:          status,
		Encrypted:       encrypted,
		ValidationBasis: validationBasis,
		ReviewReason:    reviewReason,
	}
	return []Match{match}
}

func matchedHeader(content []byte) string {
	for _, header := range privateKeyHeaders {
		if bytes.Contains(content, []byte(header)) {
			return header
		}
	}
	return ""
}

func lineForHeader(text, header string) int {
	index := strings.Index(text, header)
	if index < 0 {
		return 0
	}
	return 1 + strings.Count(text[:index], "\n")
}

func limitText(text string, max int) string {
	text = strings.TrimSpace(text)
	if max <= 0 || len(text) <= max {
		return text
	}
	return strings.TrimSpace(text[:max])
}

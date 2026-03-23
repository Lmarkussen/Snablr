package wincredinspect

import (
	"strings"

	"snablr/internal/rules"
)

type pathFamily struct {
	id          string
	name        string
	description string
	match       string
	severity    string
}

var pathFamilies = []pathFamily{
	{
		id:          "wincredinspect.path.credentials",
		name:        "Windows Credentials Store Path",
		description: "This path is inside the Windows Credentials store, which can contain DPAPI-protected saved credentials.",
		match:       "credentials",
		severity:    "high",
	},
	{
		id:          "wincredinspect.path.vault",
		name:        "Windows Vault Path",
		description: "This path is inside the Windows Vault store, which can contain DPAPI-protected web and application credentials.",
		match:       "vault",
		severity:    "high",
	},
	{
		id:          "wincredinspect.path.protect",
		name:        "Windows DPAPI Protect Path",
		description: "This path is inside the Windows DPAPI Protect store, which holds key material needed to unlock protected credential stores.",
		match:       "protect",
		severity:    "medium",
	},
}

var pathTokens = []string{
	"/appdata/roaming/microsoft/credentials/",
	"/appdata/local/microsoft/credentials/",
	"/appdata/roaming/microsoft/vault/",
	"/appdata/local/microsoft/vault/",
	"/appdata/roaming/microsoft/protect/",
	"/appdata/local/microsoft/protect/",
}

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(Candidate) bool {
	return false
}

func (Inspector) InspectMetadata(candidate Candidate) []Match {
	normalized := normalizedPath(candidate)
	if normalized == "" {
		return nil
	}

	var matches []Match
	for _, family := range pathFamilies {
		if !strings.Contains(normalized, familyToken(family.match)) {
			continue
		}
		matches = append(matches, newPathMatch(family, normalized))
	}
	return matches
}

func normalizedPath(candidate Candidate) string {
	path := strings.ReplaceAll(strings.TrimSpace(candidate.FilePath), `\`, `/`)
	return strings.ToLower(rules.NormalizePath(path))
}

func familyToken(family string) string {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "credentials":
		return "/microsoft/credentials/"
	case "vault":
		return "/microsoft/vault/"
	case "protect":
		return "/microsoft/protect/"
	default:
		return ""
	}
}

func newPathMatch(family pathFamily, normalizedPath string) Match {
	tags := []string{
		"windows",
		"dpapi",
		"artifact:windows-credstore",
		"credstore:path-exact",
		"credstore:type:" + family.match,
	}
	if family.match == "protect" {
		tags = append(tags, "credstore:type:dpapi-protect")
	}

	return Match{
		ID:                  family.id,
		Name:                family.name,
		Description:         family.description,
		RuleType:            "filename",
		SignalType:          "validated",
		Severity:            family.severity,
		Confidence:          "high",
		Category:            "windows-credentials",
		Match:               familyToken(family.match),
		MatchedText:         normalizedPath,
		MatchedTextRedacted: normalizedPath,
		Snippet:             normalizedPath,
		Context:             normalizedPath,
		ContextRedacted:     normalizedPath,
		Explanation:         family.description,
		Remediation:         "Restrict access to profile credential-store material, remove unnecessary copies from shared storage, and review whether DPAPI-protected credential artifacts belong in the scanned location.",
		Tags:                tags,
	}
}

func ProfileContext(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), `\`, `/`)
	path = strings.ToLower(rules.NormalizePath(path))
	if path == "" {
		return ""
	}

	for _, marker := range []string{"/appdata/roaming/", "/appdata/local/"} {
		if idx := strings.Index(path, marker); idx > 0 {
			return strings.Trim(path[:idx], "/")
		}
	}
	return ""
}

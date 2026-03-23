package browsercredinspect

import (
	"path/filepath"
	"strings"

	"snablr/internal/rules"
)

type artifactSpec struct {
	id          string
	name        string
	description string
	family      string
	pathToken   string
	filename    string
	severity    string
	tags        []string
}

var artifactSpecs = []artifactSpec{
	{
		id:          "browsercredinspect.firefox.logins",
		name:        "Firefox Saved Logins Artifact",
		description: "This path matches a Firefox profile `logins.json` artifact, which can contain saved browser credential metadata when paired with the corresponding Firefox key store.",
		family:      "firefox-logins",
		pathToken:   "/mozilla/firefox/profiles/",
		filename:    "logins.json",
		severity:    "medium",
		tags:        []string{"browser", "firefox", "artifact:browser-credstore", "browsercred:type:firefox-logins"},
	},
	{
		id:          "browsercredinspect.firefox.key4",
		name:        "Firefox Key Store Artifact",
		description: "This path matches a Firefox profile `key4.db` artifact, which stores key material used with Firefox saved logins.",
		family:      "firefox-key4",
		pathToken:   "/mozilla/firefox/profiles/",
		filename:    "key4.db",
		severity:    "medium",
		tags:        []string{"browser", "firefox", "artifact:browser-credstore", "browsercred:type:firefox-key4"},
	},
	{
		id:          "browsercredinspect.chromium.login_data",
		name:        "Chromium Login Data Artifact",
		description: "This path matches a Chromium-family `Login Data` artifact, which can contain saved browser credentials in the profile database.",
		family:      "chromium-login-data",
		pathToken:   "/user data/",
		filename:    "login data",
		severity:    "medium",
		tags:        []string{"browser", "chromium", "artifact:browser-credstore", "browsercred:type:chromium-login-data"},
	},
	{
		id:          "browsercredinspect.chromium.cookies",
		name:        "Chromium Cookies Artifact",
		description: "This path matches a Chromium-family `Cookies` artifact, which can contain session material associated with the browser profile.",
		family:      "chromium-cookies",
		pathToken:   "/user data/",
		filename:    "cookies",
		severity:    "low",
		tags:        []string{"browser", "chromium", "artifact:browser-credstore", "browsercred:type:chromium-cookies"},
	},
}

var chromiumRoots = []string{
	"/google/chrome/user data/",
	"/microsoft/edge/user data/",
	"/bravesoftware/brave-browser/user data/",
}

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(Candidate) bool {
	return false
}

func (Inspector) InspectMetadata(candidate Candidate) []Match {
	normalized := normalizedPath(candidate.FilePath)
	if normalized == "" {
		return nil
	}

	base := strings.ToLower(strings.TrimSpace(filepath.Base(normalized)))
	matches := make([]Match, 0, 1)
	for _, spec := range artifactSpecs {
		if base != spec.filename {
			continue
		}
		if !matchesArtifactFamily(normalized, spec) {
			continue
		}
		matches = append(matches, Match{
			ID:                  spec.id,
			Name:                spec.name,
			Description:         spec.description,
			RuleType:            "filename",
			SignalType:          "validated",
			Severity:            spec.severity,
			Confidence:          "high",
			Category:            "browser-credentials",
			Match:               spec.filename,
			MatchedText:         normalized,
			MatchedTextRedacted: normalized,
			Snippet:             normalized,
			Context:             normalized,
			ContextRedacted:     normalized,
			Explanation:         spec.description,
			Remediation:         "Restrict access to browser profile credential-store artifacts, remove unnecessary profile copies from shared storage, and review whether offline credential or session extraction is possible from the exposed profile material.",
			Tags:                append([]string{}, spec.tags...),
		})
	}
	return matches
}

func normalizedPath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), `\`, `/`)
	return strings.ToLower(rules.NormalizePath(path))
}

func matchesArtifactFamily(normalized string, spec artifactSpec) bool {
	switch spec.family {
	case "firefox-logins", "firefox-key4":
		return strings.Contains(normalized, spec.pathToken)
	case "chromium-login-data", "chromium-cookies":
		for _, root := range chromiumRoots {
			if strings.Contains(normalized, root) {
				return true
			}
		}
	}
	return false
}

func ProfileContext(path string) string {
	normalized := normalizedPath(path)
	if normalized == "" {
		return ""
	}
	if idx := strings.Index(normalized, "/mozilla/firefox/profiles/"); idx >= 0 {
		prefix := normalized[idx+len("/mozilla/firefox/profiles/"):]
		if slash := strings.Index(prefix, "/"); slash > 0 {
			return strings.Trim(normalized[:idx+len("/mozilla/firefox/profiles/")+slash], "/")
		}
	}
	for _, root := range chromiumRoots {
		if idx := strings.Index(normalized, root); idx >= 0 {
			prefix := normalized[idx+len(root):]
			if slash := strings.Index(prefix, "/"); slash > 0 {
				return strings.Trim(normalized[:idx+len(root)+slash], "/")
			}
		}
	}
	return ""
}

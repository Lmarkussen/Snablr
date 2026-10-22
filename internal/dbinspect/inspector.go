package dbinspect

import (
	"strconv"
	"strings"
)

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(candidate Candidate) bool {
	name := normalizedName(candidate)
	ext := normalizedExtension(candidate)
	if _, ok := exactArtifactFiles[name]; ok {
		return true
	}
	switch ext {
	case ".dsn", ".sql", ".udl", ".ora":
		return true
	}
	if _, ok := textLikeExtensions[ext]; !ok {
		return false
	}

	candidatePath := strings.ToLower(normalizedPath(candidate))
	for _, token := range dbHintTokens {
		if strings.Contains(candidatePath, token) || strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func (Inspector) InspectMetadata(candidate Candidate) []Match {
	name := normalizedName(candidate)
	ext := normalizedExtension(candidate)

	var matches []Match
	seen := make(map[string]struct{})
	if def, ok := exactArtifactFiles[name]; ok {
		match := artifactMatch(def, name, "filename")
		matches = append(matches, match)
		seen[match.ID] = struct{}{}
	}
	if def, ok := extensionArtifacts[ext]; ok {
		match := artifactMatch(def, ext, "extension")
		if _, exists := seen[match.ID]; !exists {
			matches = append(matches, match)
		}
	}
	if match, ok := backupArtifactMatch(candidate); ok {
		if _, exists := seen[match.ID]; !exists {
			matches = append(matches, match)
		}
	}
	return matches
}

func (Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	seen := make(map[string]struct{})
	matches := inspectSQLiteArtifact(candidate, content, seen)
	text := normalizedContent(content)
	if text == "" {
		return matches
	}

	matches = append(matches, inspectOracleTNS(candidate, text, seen)...)
	matches = append(matches, inspectINISections(text, seen)...)
	matches = append(matches, inspectScopedCredentialFields(text, seen)...)
	matches = append(matches, inspectSQLDump(candidate, text, seen)...)
	matches = append(matches, inspectStructuredDatabaseConfig(candidate, content, text, seen)...)

	lines := strings.Split(text, "\n")
	for idx, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		for _, fragment := range candidateFragments(line) {
			if observation, ok := inspectKVFragment(fragment, idx+1); ok {
				key := observation.id + "::" + strings.ToLower(observation.match)
				if strings.HasPrefix(observation.id, "dbinspect.infrastructure.") {
					key = observation.id + "::" + strconv.Itoa(observation.lineNumber) + "::" + strings.ToLower(observation.match)
				}
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					matches = append(matches, matchFromObservation(observation, fragment))
				}
			}
			if observation, ok := inspectURLFragment(fragment, idx+1); ok {
				key := observation.id + "::" + strings.ToLower(observation.match)
				if strings.HasPrefix(observation.id, "dbinspect.infrastructure.") {
					key = observation.id + "::" + strconv.Itoa(observation.lineNumber) + "::" + strings.ToLower(observation.match)
				}
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					matches = append(matches, matchFromObservation(observation, fragment))
				}
			}
		}
	}

	return matches
}

package dbinspect

import "strings"

func artifactMatch(def artifactDefinition, matchedValue, ruleType string) Match {
	return Match{
		ID:                  def.id,
		Name:                def.name,
		Description:         def.description,
		RuleType:            ruleType,
		SignalType:          "validated",
		Severity:            "medium",
		Confidence:          "high",
		Category:            "database-artifacts",
		Match:               matchedValue,
		MatchedText:         matchedValue,
		MatchedTextRedacted: matchedValue,
		Snippet:             matchedValue,
		Context:             matchedValue,
		ContextRedacted:     matchedValue,
		Explanation:         def.description,
		Remediation:         "Review who can access this database artifact, confirm it is expected in the share, and remove or relocate it if it does not belong in broadly accessible storage.",
		Tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:artifact",
			"db:ecosystem:" + def.ecosystem,
		},
	}
}

func backupArtifactMatch(candidate Candidate) (Match, bool) {
	ext := normalizedExtension(candidate)
	ecosystem, ok := backupArtifactExtensions[ext]
	if !ok {
		return Match{}, false
	}

	name := strings.TrimSuffix(normalizedName(candidate), ext)
	if !containsAny(name, databaseBackupTokens...) {
		return Match{}, false
	}

	return Match{
		ID:                  "dbinspect.artifact.database_backup",
		Name:                "Database Backup Artifact",
		Description:         "This file looks like a database backup artifact based on both extension and database-specific path or filename context.",
		RuleType:            "extension",
		SignalType:          "validated",
		Severity:            "medium",
		Confidence:          "high",
		Category:            "database-artifacts",
		Match:               ext,
		MatchedText:         ext,
		MatchedTextRedacted: ext,
		Snippet:             ext,
		Context:             normalizedPath(candidate),
		ContextRedacted:     normalizedPath(candidate),
		Explanation:         "This finding requires both a backup-style extension and database-specific naming context.",
		Remediation:         "Review whether this database backup belongs on the share, remove unnecessary copies, and restrict access to retained backup artifacts.",
		Tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:backup-artifact",
			"db:ecosystem:" + ecosystem,
		},
	}, true
}

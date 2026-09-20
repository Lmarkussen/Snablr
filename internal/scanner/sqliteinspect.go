package scanner

import (
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/sqliteinspect"
)

func sqliteCandidate(meta FileMetadata) sqliteinspect.Candidate {
	return sqliteinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromSQLiteMatches(meta FileMetadata, matches []sqliteinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromSQLiteMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		})
		if filePath := strings.TrimSpace(match.Match); filePath != "" {
			finding.FilePath = filePath
		}
		finding.DatabaseFilePath = strings.TrimSpace(match.DatabaseFilePath)
		finding.DatabaseTable = strings.TrimSpace(match.DatabaseTable)
		finding.DatabaseColumn = strings.TrimSpace(match.DatabaseColumn)
		finding.DatabaseRowContext = strings.TrimSpace(match.DatabaseRowContext)
		findings = append(findings, finding)
	}
	return findings
}

func (e *Engine) recordSQLiteCredentialCandidates(meta FileMetadata, matches []sqliteinspect.Match) {
	if e == nil || e.candidateSink == nil || len(matches) == 0 {
		return
	}

	for _, match := range matches {
		switch match.ID {
		case "sqliteinspect.credentials.sensitive_value", "sqliteinspect.access.connection_string":
		default:
			continue
		}

		path := strings.TrimSpace(match.DatabaseFilePath)
		if path == "" {
			path = meta.FilePath
		}
		candidate := credentialanalysis.Candidate{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  sqliteCredentialType(match.DatabaseColumn),
			Identity:        sqliteIdentityFromRowContext(match.DatabaseRowContext),
			Value:           match.MatchedText,
			Source:          meta.Source,
			Host:            meta.Host,
			Share:           meta.Share,
			Path:            path,
			Container:       meta.ArchivePath,
			ValidationBasis: "sqlite_inspection",
			Evidence: []credentialanalysis.Evidence{{
				RuleID:   match.ID,
				Source:   meta.Source,
				Path:     meta.FilePath,
				Location: strings.TrimSpace(match.Match),
			}},
		}
		if err := e.candidateSink.RecordCredentialCandidate(candidate); err != nil && e.log != nil {
			e.log.Errorf("SQLite credential candidate recording failed for %s: %v", meta.FilePath, err)
		}
	}
}

func sqliteCredentialType(column string) string {
	column = strings.ToLower(strings.TrimSpace(column))
	switch {
	case strings.Contains(column, "password"), strings.Contains(column, "passwd"), strings.Contains(column, "pwd"):
		return "password"
	case strings.Contains(column, "api_key"), strings.Contains(column, "apikey"):
		return "api_key"
	case strings.Contains(column, "token"), strings.Contains(column, "client_secret"):
		return "token"
	case strings.Contains(column, "connection"), strings.Contains(column, "dsn"), strings.Contains(column, "db_url"), strings.Contains(column, "database_url"):
		return "connection_string"
	default:
		return "secret"
	}
}

func sqliteIdentityFromRowContext(rowContext string) string {
	for _, part := range strings.Split(rowContext, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "username", "user", "account", "email":
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		}
	}
	return ""
}

func ruleFromSQLiteMatch(match sqliteinspect.Match) rules.Rule {
	ruleType := rules.RuleTypeContent
	switch strings.ToLower(strings.TrimSpace(match.RuleType)) {
	case "filename":
		ruleType = rules.RuleTypeFilename
	case "extension":
		ruleType = rules.RuleTypeExtension
	}

	return rules.Rule{
		ID:          strings.TrimSpace(match.ID),
		Name:        strings.TrimSpace(match.Name),
		Description: strings.TrimSpace(match.Description),
		Type:        ruleType,
		Severity:    rules.Severity(strings.TrimSpace(match.Severity)),
		Confidence:  rules.Confidence(strings.TrimSpace(match.Confidence)),
		Category:    strings.TrimSpace(match.Category),
		Tags:        append([]string{}, match.Tags...),
		Explanation: strings.TrimSpace(match.Explanation),
		Remediation: strings.TrimSpace(match.Remediation),
	}
}

package scanner

import (
	"strings"

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

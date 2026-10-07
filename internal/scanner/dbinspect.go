package scanner

import (
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/dbinspect"
	"snablr/internal/rules"
)

func dbCandidate(meta FileMetadata) dbinspect.Candidate {
	return dbinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromDBMatches(meta FileMetadata, matches []dbinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, newFinding(ruleFromDBMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		}))
	}
	return findings
}

func (e *Engine) recordDBConnectionCandidates(meta FileMetadata, matches []dbinspect.Match) {
	if e == nil || e.candidateSink == nil || len(matches) == 0 {
		return
	}
	for _, match := range matches {
		if match.ID != "dbinspect.access.connection_string" {
			continue
		}
		// Only a connection string that carries an actual password is confirmed
		// credential material. A medium connection-string match (endpoint/user
		// only, or a metadata-shaped password that was rejected) is
		// infrastructure context, not an exported credential.
		if !strings.EqualFold(strings.TrimSpace(match.Severity), "high") {
			continue
		}
		candidate := credentialanalysis.Candidate{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "connection_string",
			Value:           match.MatchedText,
			Source:          meta.Source,
			Host:            meta.Host,
			Share:           meta.Share,
			Path:            meta.FilePath,
			Container:       meta.ArchivePath,
			ValidationBasis: "validated_database_connection_string",
			Evidence: []credentialanalysis.Evidence{{
				RuleID:   match.ID,
				Source:   meta.Source,
				Path:     meta.FilePath,
				Location: strings.TrimSpace(match.Match),
			}},
		}
		if err := e.candidateSink.RecordCredentialCandidate(candidate); err != nil && e.log != nil {
			e.log.Errorf("database credential candidate recording failed for %s: %v", meta.FilePath, err)
		}
	}
}

func ruleFromDBMatch(match dbinspect.Match) rules.Rule {
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

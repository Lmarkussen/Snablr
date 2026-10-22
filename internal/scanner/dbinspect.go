package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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
		observationID := strings.TrimSpace(match.ObservationID)
		ruleID := strings.ToLower(strings.TrimSpace(match.ID))
		if observationID == "" && (strings.HasPrefix(ruleID, "dbinspect.infrastructure.") || ruleID == "dbinspect.artifact.sqlite_structural") {
			observationID = fmt.Sprintf("%s|%s|%d", match.ID, strings.TrimSpace(match.Match), match.LineNumber)
		}
		if observationID != "" && (strings.HasPrefix(ruleID, "dbinspect.") || ruleID == "dbinspect.artifact.sqlite_structural") {
			observationID = sourceScopedDBObservationID(meta, match.ID, observationID)
		}
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
		findings[len(findings)-1].ObservationID = observationID
	}
	return findings
}

func sourceScopedDBObservationID(meta FileMetadata, ruleID, observationID string) string {
	hash := sha256.New()
	hash.Write([]byte("snablr:p4:db-observation:v1\x00"))
	for _, component := range []string{
		meta.Source,
		meta.Host,
		meta.Share,
		meta.FilePath,
		meta.ArchivePath,
		meta.ArchiveMemberPath,
		ruleID,
		observationID,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(component)))
		hash.Write(length[:])
		hash.Write([]byte(component))
	}
	return fmt.Sprintf("p4obs-v1:%x", hash.Sum(nil))
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

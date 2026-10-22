package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"snablr/internal/rules"
	"snablr/internal/sccminspect"
)

func sccmCandidate(meta FileMetadata) sccminspect.Candidate {
	return sccminspect.Candidate{FilePath: meta.FilePath, Name: meta.Name, Extension: meta.Extension, Size: meta.Size}
}

func findingsFromSCCMMatches(meta FileMetadata, matches []sccminspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromSCCMMatch(match), meta, findingEvidence{SignalType: match.SignalType, Match: match.Match, MatchedText: match.MatchedText, MatchedTextRedacted: match.MatchedText, Snippet: match.Snippet, Context: match.Context})
		finding.ObservationID = sourceScopedSCCMObservationID(meta, match.ID, match.ObservationKey)
		finding.TriageClass = "review"
		finding.Actionable = false
		finding.Tags = append(finding.Tags, "sccm-artifact")
		findings = append(findings, finding)
	}
	return findings
}

func sourceScopedSCCMObservationID(meta FileMetadata, ruleID, discriminator string) string {
	hash := sha256.New()
	writePart := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	writePart("snablr:p6:sccm-observation:v1")
	writePart(strings.ToLower(strings.TrimSpace(meta.Host)))
	writePart(strings.ToLower(strings.TrimSpace(meta.Share)))
	writePart(strings.TrimSpace(meta.FilePath))
	writePart(strings.TrimSpace(meta.ArchivePath))
	writePart(strings.TrimSpace(meta.ArchiveMemberPath))
	writePart(strings.TrimSpace(ruleID))
	writePart(strings.TrimSpace(discriminator))
	return "sccminspect:" + hex.EncodeToString(hash.Sum(nil))
}

func ruleFromSCCMMatch(match sccminspect.Match) rules.Rule {
	return rules.Rule{ID: strings.TrimSpace(match.ID), Name: strings.TrimSpace(match.Name), Description: strings.TrimSpace(match.Description), Type: rules.RuleTypeContent, Severity: rules.Severity(strings.TrimSpace(match.Severity)), Confidence: rules.Confidence(strings.TrimSpace(match.Confidence)), Category: strings.TrimSpace(match.Category), Tags: append([]string{}, match.Tags...), Explanation: strings.TrimSpace(match.ValidationBasis)}
}

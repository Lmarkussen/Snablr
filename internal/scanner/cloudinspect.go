package scanner

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"snablr/internal/cloudinspect"
	"snablr/internal/rules"
)

func cloudCandidate(meta FileMetadata) cloudinspect.Candidate {
	return cloudinspect.Candidate{FilePath: meta.FilePath, Name: meta.Name, Extension: meta.Extension, Size: meta.Size}
}

func findingsFromCloudMatches(meta FileMetadata, matches []cloudinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromCloudMatch(match), meta, findingEvidence{
			SignalType: match.SignalType, Match: match.Match, MatchedText: match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted, Snippet: match.Snippet,
			Context: match.Context, ContextRedacted: match.ContextRedacted, LineNumber: match.LineNumber,
		})
		finding.ObservationID = sourceScopedCloudObservationID(meta, match.ID, match.ObservationKey)
		findings = append(findings, finding)
	}
	return findings
}

func sourceScopedCloudObservationID(meta FileMetadata, ruleID, discriminator string) string {
	hash := sha256.New()
	writePart := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		hash.Write(length[:])
		hash.Write([]byte(value))
	}
	writePart("snablr:p5:cloud-observation:v1")
	writePart(strings.ToLower(strings.TrimSpace(meta.Host)))
	writePart(strings.ToLower(strings.TrimSpace(meta.Share)))
	writePart(strings.TrimSpace(meta.FilePath))
	writePart(strings.TrimSpace(meta.ArchivePath))
	writePart(strings.TrimSpace(meta.ArchiveMemberPath))
	writePart(strings.TrimSpace(ruleID))
	writePart(strings.TrimSpace(discriminator))
	return "cloudinspect:" + hex.EncodeToString(hash.Sum(nil))
}

func ruleFromCloudMatch(match cloudinspect.Match) rules.Rule {
	ruleType := rules.RuleTypeContent
	if strings.EqualFold(strings.TrimSpace(match.RuleType), "filename") {
		ruleType = rules.RuleTypeFilename
	}
	return rules.Rule{ID: strings.TrimSpace(match.ID), Name: strings.TrimSpace(match.Name), Description: strings.TrimSpace(match.Description), Type: ruleType, Severity: rules.Severity(strings.TrimSpace(match.Severity)), Confidence: rules.Confidence(strings.TrimSpace(match.Confidence)), Category: strings.TrimSpace(match.Category), Tags: append([]string{}, match.Tags...), Explanation: strings.TrimSpace(match.Explanation), Remediation: strings.TrimSpace(match.Remediation)}
}

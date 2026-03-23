package scanner

import (
	"strings"

	"snablr/internal/backupinspect"
	"snablr/internal/rules"
)

func backupCandidate(meta FileMetadata) backupinspect.Candidate {
	return backupinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromBackupMatches(meta FileMetadata, matches []backupinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromBackupMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		})
		finding.MatchReason = "path matched an exact backup or system-state storage family covered by the built-in artifact inspector."
		finding.SupportingSignals = append(finding.SupportingSignals, SupportingSignal{
			SignalType: "path",
			Weight:     baseSignalWeight("path"),
			Reason:     "path matched an exact backup or copied system-state family such as WindowsImageBackup, System Volume Information, RegBack, or Windows repair",
		})
		finding.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(append(finding.MatchedSignalTypes, "path")))
		findings = append(findings, finding)
	}
	return findings
}

func ruleFromBackupMatch(match backupinspect.Match) rules.Rule {
	return rules.Rule{
		ID:          strings.TrimSpace(match.ID),
		Name:        strings.TrimSpace(match.Name),
		Description: strings.TrimSpace(match.Description),
		Type:        rules.RuleTypeFilename,
		Severity:    rules.Severity(strings.TrimSpace(match.Severity)),
		Confidence:  rules.Confidence(strings.TrimSpace(match.Confidence)),
		Category:    strings.TrimSpace(match.Category),
		Tags:        append([]string{}, match.Tags...),
		Explanation: strings.TrimSpace(match.Explanation),
		Remediation: strings.TrimSpace(match.Remediation),
	}
}

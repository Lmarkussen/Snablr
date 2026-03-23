package scanner

import (
	"strings"

	"snablr/internal/rules"
	"snablr/internal/wincredinspect"
)

func winCredCandidate(meta FileMetadata) wincredinspect.Candidate {
	return wincredinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromWinCredMatches(meta FileMetadata, matches []wincredinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromWinCredMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		})
		finding.MatchReason = "path matched an exact Windows credential-store location covered by the built-in artifact inspector."
		finding.SupportingSignals = append(finding.SupportingSignals, SupportingSignal{
			SignalType: "path",
			Weight:     baseSignalWeight("path"),
			Reason:     "path matched an exact Windows credential-store family under AppData/Microsoft",
		})
		finding.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(append(finding.MatchedSignalTypes, "path")))
		findings = append(findings, finding)
	}
	return findings
}

func ruleFromWinCredMatch(match wincredinspect.Match) rules.Rule {
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

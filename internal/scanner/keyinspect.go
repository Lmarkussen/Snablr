package scanner

import (
	"strings"

	"snablr/internal/keyinspect"
	"snablr/internal/rules"
)

func keyCandidate(meta FileMetadata) keyinspect.Candidate {
	return keyinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromKeyMatches(meta FileMetadata, matches []keyinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, newFinding(ruleFromKeyMatch(match), meta, findingEvidence{
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

func ruleFromKeyMatch(match keyinspect.Match) rules.Rule {
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

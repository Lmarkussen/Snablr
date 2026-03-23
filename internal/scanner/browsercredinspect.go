package scanner

import (
	"strings"

	"snablr/internal/browsercredinspect"
	"snablr/internal/rules"
)

func browserCredCandidate(meta FileMetadata) browsercredinspect.Candidate {
	return browsercredinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromBrowserCredMatches(meta FileMetadata, matches []browsercredinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromBrowserCredMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		})
		finding.MatchReason = "path matched an exact browser credential-store artifact covered by the built-in artifact inspector."
		finding.SupportingSignals = append(finding.SupportingSignals, SupportingSignal{
			SignalType: "path",
			Weight:     baseSignalWeight("path"),
			Reason:     "path matched an exact browser profile credential-store family such as Firefox Profiles or Chromium User Data",
		})
		finding.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(append(finding.MatchedSignalTypes, "path")))
		findings = append(findings, finding)
	}
	return findings
}

func downgradeBrowserArtifactFinding(f Finding) Finding {
	f.TriageClass = triageWeakReview
	f.Actionable = false
	f.Correlated = false
	if severityRank(f.Severity) > severityRank("medium") {
		f.Severity = "medium"
	}
	if f.ConfidenceScore > 34 {
		f.ConfidenceScore = 34
	}
	if strings.TrimSpace(f.Confidence) == "" || confidenceRank(f.Confidence) > confidenceRank("medium") {
		f.Confidence = "medium"
	}
	f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "browser credential-store artifact was identified without decryption or direct credential extraction")
	f.ConfidenceBreakdown.TriageAdjustment = f.ConfidenceScore - f.ConfidenceBreakdown.BaseScore
	f.ConfidenceBreakdown.FinalScore = f.ConfidenceScore
	return f
}

func adjustBrowserArtifactVisibility(findings []Finding) []Finding {
	for i := range findings {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(findings[i].RuleID)), "browsercredinspect.") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(findings[i].SignalType), "correlation") {
			continue
		}
		findings[i] = downgradeBrowserArtifactFinding(findings[i])
	}
	return findings
}

func ruleFromBrowserCredMatch(match browsercredinspect.Match) rules.Rule {
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

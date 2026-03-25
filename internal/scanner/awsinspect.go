package scanner

import (
	"strings"

	"snablr/internal/awsinspect"
	"snablr/internal/rules"
)

func awsCandidate(meta FileMetadata) awsinspect.Candidate {
	return awsinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}
}

func findingsFromAWSMatches(meta FileMetadata, matches []awsinspect.Match) []Finding {
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		finding := newFinding(ruleFromAWSMatch(match), meta, findingEvidence{
			SignalType:          strings.TrimSpace(match.SignalType),
			Match:               strings.TrimSpace(match.Match),
			MatchedText:         match.MatchedText,
			MatchedTextRedacted: match.MatchedTextRedacted,
			Snippet:             match.Snippet,
			Context:             match.Context,
			ContextRedacted:     match.ContextRedacted,
			LineNumber:          match.LineNumber,
		})
		ruleID := strings.ToLower(strings.TrimSpace(match.ID))
		if strings.HasPrefix(ruleID, "awsinspect.path.") {
			finding.SupportingSignals = append(finding.SupportingSignals, SupportingSignal{
				SignalType: "path",
				Weight:     baseSignalWeight("path"),
				Reason:     "path matched an exact AWS shared profile artifact under a normalized .aws directory",
			})
			finding.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(append(finding.MatchedSignalTypes, "path")))
			if strings.TrimSpace(finding.MatchReason) == "" {
				finding.MatchReason = "path matched an exact AWS shared-profile artifact."
			}
		}
		if ruleID == "awsinspect.content.credentials_bundle" {
			if kind, _ := awsArtifactKind(meta.FilePath); kind == "credentials" {
				finding.SupportingSignals = append(finding.SupportingSignals, SupportingSignal{
					SignalType: "path",
					Weight:     baseSignalWeight("path"),
					Reason:     "validated credential material came from an exact AWS shared credentials artifact path",
				})
				finding.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(append(finding.MatchedSignalTypes, "path")))
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

func awsArtifactKind(path string) (string, bool) {
	kind := awsinspect.New().InspectMetadata(awsinspect.Candidate{FilePath: path})
	if len(kind) == 1 {
		switch strings.ToLower(strings.TrimSpace(kind[0].ID)) {
		case "awsinspect.path.credentials":
			return "credentials", true
		case "awsinspect.path.config":
			return "config", true
		}
	}
	return "", false
}

func adjustAWSArtifactVisibility(findings []Finding) []Finding {
	for i := range findings {
		ruleID := strings.ToLower(strings.TrimSpace(findings[i].RuleID))
		if ruleID != "awsinspect.path.config" {
			continue
		}
		findings[i] = downgradeAWSConfigArtifactFinding(findings[i])
	}
	return findings
}

func downgradeAWSConfigArtifactFinding(f Finding) Finding {
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
	f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "AWS shared config was identified without credential material and is retained as supporting context")
	f.ConfidenceBreakdown.TriageAdjustment = f.ConfidenceScore - f.ConfidenceBreakdown.BaseScore
	f.ConfidenceBreakdown.FinalScore = f.ConfidenceScore
	return f
}

func ruleFromAWSMatch(match awsinspect.Match) rules.Rule {
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

package scanner

import "snablr/internal/rules"

type FilenameScanner struct{}

type ExtensionScanner struct{}

func (s FilenameScanner) Scan(ruleSet []rules.Rule, meta FileMetadata) []Finding {
	findings := make([]Finding, 0)
	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if !ruleMatchesMetadata(rule, meta) {
			continue
		}

		match, ok := firstMatch(rule, meta.Name)
		if !ok {
			continue
		}
		findings = append(findings, newFinding(rule, meta, heuristicEvidence(rule.Type, match)))
	}
	return findings
}

func (s ExtensionScanner) Scan(ruleSet []rules.Rule, meta FileMetadata) []Finding {
	findings := make([]Finding, 0)
	normalizedExt := normalizeExtension(meta.Extension)
	if normalizedExt == "" {
		return findings
	}

	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if !ruleMatchesMetadata(rule, meta) {
			continue
		}

		match, ok := firstMatch(rule, normalizedExt)
		if !ok {
			continue
		}
		findings = append(findings, newFinding(rule, meta, heuristicEvidence(rule.Type, match)))
	}
	return findings
}

package diff

import (
	"sort"
	"strings"

	"snablr/internal/scanner"
)

func Compare(previous, current []scanner.Finding) DiffResult {
	prevByFingerprint := make(map[FindingFingerprint]scanner.Finding, len(previous))
	for _, finding := range previous {
		prevByFingerprint[Fingerprint(finding)] = cloneFinding(finding)
	}

	currByFingerprint := make(map[FindingFingerprint]scanner.Finding, len(current))
	for _, finding := range current {
		currByFingerprint[Fingerprint(finding)] = cloneFinding(finding)
	}

	result := DiffResult{
		New:       make([]scanner.Finding, 0),
		Removed:   make([]scanner.Finding, 0),
		Changed:   make([]ChangedFinding, 0),
		Unchanged: make([]scanner.Finding, 0),
	}

	for fp, curr := range currByFingerprint {
		prev, ok := prevByFingerprint[fp]
		if !ok {
			result.New = append(result.New, curr)
			continue
		}

		changedFields := compareFields(prev, curr)
		if len(changedFields) == 0 {
			result.Unchanged = append(result.Unchanged, curr)
			continue
		}

		result.Changed = append(result.Changed, ChangedFinding{
			Previous:      prev,
			Current:       curr,
			Fingerprint:   fp,
			ChangedFields: changedFields,
		})
	}

	for fp, prev := range prevByFingerprint {
		if _, ok := currByFingerprint[fp]; ok {
			continue
		}
		result.Removed = append(result.Removed, prev)
	}

	sort.Slice(result.New, func(i, j int) bool { return findingSortKey(result.New[i]) < findingSortKey(result.New[j]) })
	sort.Slice(result.Removed, func(i, j int) bool { return findingSortKey(result.Removed[i]) < findingSortKey(result.Removed[j]) })
	sort.Slice(result.Unchanged, func(i, j int) bool { return findingSortKey(result.Unchanged[i]) < findingSortKey(result.Unchanged[j]) })
	sort.Slice(result.Changed, func(i, j int) bool {
		return findingSortKey(result.Changed[i].Current) < findingSortKey(result.Changed[j].Current)
	})

	return result
}

func CurrentStatuses(result DiffResult) map[FindingFingerprint]FindingDelta {
	statuses := make(map[FindingFingerprint]FindingDelta, len(result.New)+len(result.Changed)+len(result.Unchanged))

	for _, finding := range result.New {
		fp := Fingerprint(finding)
		statuses[fp] = FindingDelta{
			Status:      StatusNew,
			Fingerprint: fp,
		}
	}
	for _, changed := range result.Changed {
		statuses[changed.Fingerprint] = FindingDelta{
			Status:        StatusChanged,
			Fingerprint:   changed.Fingerprint,
			ChangedFields: append([]string{}, changed.ChangedFields...),
		}
	}
	for _, finding := range result.Unchanged {
		fp := Fingerprint(finding)
		statuses[fp] = FindingDelta{
			Status:      StatusUnchanged,
			Fingerprint: fp,
		}
	}

	return statuses
}

func Fingerprint(f scanner.Finding) FindingFingerprint {
	ruleID := normalizeIdentity(f.RuleID)
	if len(f.MatchedRuleIDs) > 0 {
		ruleID = normalizeIdentity(strings.Join(sortedStrings(f.MatchedRuleIDs), "|"))
	}
	return FindingFingerprint{
		RuleID:   ruleID,
		Host:     normalizeIdentity(f.Host),
		Share:    normalizeIdentity(f.Share),
		FilePath: normalizePathIdentity(f.FilePath),
		Match:    normalizeIdentity(f.Match),
	}
}

func normalizeIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizePathIdentity(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\`, `/`)
	return strings.ToLower(value)
}

func compareFields(previous, current scanner.Finding) []string {
	fields := make([]string, 0, 12)

	if !strings.EqualFold(strings.TrimSpace(previous.RuleName), strings.TrimSpace(current.RuleName)) {
		fields = append(fields, "rule_name")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.Severity), strings.TrimSpace(current.Severity)) {
		fields = append(fields, "severity")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.Confidence), strings.TrimSpace(current.Confidence)) {
		fields = append(fields, "confidence")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.RuleConfidence), strings.TrimSpace(current.RuleConfidence)) {
		fields = append(fields, "rule_confidence")
	}
	if previous.ConfidenceScore != current.ConfidenceScore {
		fields = append(fields, "confidence_score")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.Category), strings.TrimSpace(current.Category)) {
		fields = append(fields, "category")
	}
	if previous.Priority != current.Priority {
		fields = append(fields, "priority")
	}
	if strings.TrimSpace(previous.PriorityReason) != strings.TrimSpace(current.PriorityReason) {
		fields = append(fields, "priority_reason")
	}
	if previous.SharePriority != current.SharePriority {
		fields = append(fields, "share_priority")
	}
	if strings.TrimSpace(previous.SharePriorityReason) != strings.TrimSpace(current.SharePriorityReason) {
		fields = append(fields, "share_priority_reason")
	}
	if strings.TrimSpace(previous.ShareDescription) != strings.TrimSpace(current.ShareDescription) {
		fields = append(fields, "share_description")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.ShareType), strings.TrimSpace(current.ShareType)) {
		fields = append(fields, "share_type")
	}
	if !strings.EqualFold(strings.TrimSpace(previous.Source), strings.TrimSpace(current.Source)) {
		fields = append(fields, "source")
	}
	if strings.TrimSpace(previous.DFSNamespacePath) != strings.TrimSpace(current.DFSNamespacePath) {
		fields = append(fields, "dfs_namespace_path")
	}
	if strings.TrimSpace(previous.DFSLinkPath) != strings.TrimSpace(current.DFSLinkPath) {
		fields = append(fields, "dfs_link_path")
	}
	if strings.TrimSpace(previous.Snippet) != strings.TrimSpace(current.Snippet) {
		fields = append(fields, "match_snippet")
	}
	if strings.TrimSpace(previous.MatchReason) != strings.TrimSpace(current.MatchReason) {
		fields = append(fields, "match_reason")
	}
	if strings.TrimSpace(previous.RuleExplanation) != strings.TrimSpace(current.RuleExplanation) {
		fields = append(fields, "rule_explanation")
	}
	if strings.TrimSpace(previous.RuleRemediation) != strings.TrimSpace(current.RuleRemediation) {
		fields = append(fields, "rule_remediation")
	}
	if previous.FromSYSVOL != current.FromSYSVOL {
		fields = append(fields, "from_sysvol")
	}
	if previous.FromNETLOGON != current.FromNETLOGON {
		fields = append(fields, "from_netlogon")
	}
	if !equalStringSlices(previous.Tags, current.Tags) {
		fields = append(fields, "tags")
	}
	if !equalStringSlices(previous.MatchedRuleIDs, current.MatchedRuleIDs) {
		fields = append(fields, "matched_rule_ids")
	}
	if !equalStringSlices(previous.MatchedSignalTypes, current.MatchedSignalTypes) {
		fields = append(fields, "matched_signal_types")
	}
	if !equalStringSlices(previous.ConfidenceReasons, current.ConfidenceReasons) {
		fields = append(fields, "confidence_reasons")
	}
	if !equalSignals(previous.SupportingSignals, current.SupportingSignals) {
		fields = append(fields, "supporting_signals")
	}

	return fields
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	leftCopy := append([]string{}, left...)
	rightCopy := append([]string{}, right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func cloneFinding(f scanner.Finding) scanner.Finding {
	out := f
	out.Tags = append([]string{}, f.Tags...)
	out.MatchedRuleIDs = append([]string{}, f.MatchedRuleIDs...)
	out.MatchedSignalTypes = append([]string{}, f.MatchedSignalTypes...)
	out.ConfidenceReasons = append([]string{}, f.ConfidenceReasons...)
	out.SupportingSignals = append([]scanner.SupportingSignal{}, f.SupportingSignals...)
	return out
}

func findingSortKey(f scanner.Finding) string {
	fp := Fingerprint(f)
	return strings.Join([]string{fp.RuleID, fp.Host, fp.Share, fp.FilePath, fp.Match}, "|")
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func equalSignals(left, right []scanner.SupportingSignal) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]scanner.SupportingSignal{}, left...)
	rightCopy := append([]scanner.SupportingSignal{}, right...)
	sort.Slice(leftCopy, func(i, j int) bool {
		return signalSortKey(leftCopy[i]) < signalSortKey(leftCopy[j])
	})
	sort.Slice(rightCopy, func(i, j int) bool {
		return signalSortKey(rightCopy[i]) < signalSortKey(rightCopy[j])
	})
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func signalSortKey(signal scanner.SupportingSignal) string {
	return strings.Join([]string{
		signal.SignalType,
		signal.RuleID,
		signal.RuleName,
		signal.Match,
		signal.Confidence,
		signal.Reason,
	}, "|")
}

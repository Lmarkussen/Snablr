package scanner

import (
	"fmt"
	"sort"
	"strings"
)

var signalWeightCaps = map[string]int{
	"content":          40,
	"filename":         24,
	"extension":        14,
	"path":             12,
	"share_priority":   12,
	"planner_priority": 14,
}

func correlateFindings(meta FileMetadata, findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	type bucketKey struct {
		host     string
		share    string
		path     string
		category string
	}

	grouped := make(map[bucketKey][]Finding, len(findings))
	for _, finding := range findings {
		key := bucketKey{
			host:     strings.ToLower(strings.TrimSpace(finding.Host)),
			share:    strings.ToLower(strings.TrimSpace(finding.Share)),
			path:     strings.ToLower(strings.TrimSpace(finding.FilePath)),
			category: strings.ToLower(strings.TrimSpace(finding.Category)),
		}
		grouped[key] = append(grouped[key], finding)
	}

	out := make([]Finding, 0, len(grouped))
	for _, group := range grouped {
		out = append(out, correlateGroup(meta, group))
	}

	sort.Slice(out, func(i, j int) bool {
		if severityRank(out[i].Severity) == severityRank(out[j].Severity) {
			if out[i].Category == out[j].Category {
				return out[i].FilePath < out[j].FilePath
			}
			return out[i].Category < out[j].Category
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})

	return out
}

func correlateGroup(meta FileMetadata, group []Finding) Finding {
	primary := selectPrimaryFinding(group)
	correlated := primary

	var (
		ruleIDs       []string
		signalTypes   []string
		tags          []string
		reasons       []string
		signals       []SupportingSignal
		weightsByType = make(map[string]int)
	)

	for _, finding := range group {
		ruleIDs = append(ruleIDs, finding.RuleID)
		tags = append(tags, finding.Tags...)
		for _, signal := range finding.SupportingSignals {
			signals = append(signals, signal)
			signalTypes = append(signalTypes, signal.SignalType)
			weightsByType[signal.SignalType] += signal.Weight
			if signal.Reason != "" {
				reasons = append(reasons, signal.Reason)
			}
		}
		if correlated.Match == "" && finding.Match != "" {
			correlated.Match = finding.Match
		}
		if correlated.SignalType == "" && finding.SignalType != "" {
			correlated.SignalType = finding.SignalType
		}
		if correlated.MatchedText == "" && finding.MatchedText != "" {
			correlated.MatchedText = finding.MatchedText
		}
		if correlated.MatchedTextRedacted == "" && finding.MatchedTextRedacted != "" {
			correlated.MatchedTextRedacted = finding.MatchedTextRedacted
		}
		if correlated.Snippet == "" && finding.Snippet != "" {
			correlated.Snippet = finding.Snippet
		}
		if correlated.Context == "" && finding.Context != "" {
			correlated.Context = finding.Context
		}
		if correlated.ContextRedacted == "" && finding.ContextRedacted != "" {
			correlated.ContextRedacted = finding.ContextRedacted
		}
		if correlated.PotentialAccount == "" && finding.PotentialAccount != "" {
			correlated.PotentialAccount = finding.PotentialAccount
		}
		if correlated.LineNumber == 0 && finding.LineNumber > 0 {
			correlated.LineNumber = finding.LineNumber
		}
		if severityRank(finding.Severity) > severityRank(correlated.Severity) {
			correlated.Severity = finding.Severity
		}
		if correlated.RuleExplanation == "" && finding.RuleExplanation != "" {
			correlated.RuleExplanation = finding.RuleExplanation
		}
		if correlated.RuleRemediation == "" && finding.RuleRemediation != "" {
			correlated.RuleRemediation = finding.RuleRemediation
		}
	}

	if signal, ok := pathContextSignal(meta); ok {
		signals = append(signals, signal)
		signalTypes = append(signalTypes, signal.SignalType)
		weightsByType[signal.SignalType] += signal.Weight
		reasons = append(reasons, signal.Reason)
	}
	if signal, ok := sharePrioritySignal(meta); ok {
		signals = append(signals, signal)
		signalTypes = append(signalTypes, signal.SignalType)
		weightsByType[signal.SignalType] += signal.Weight
		reasons = append(reasons, signal.Reason)
	}
	if signal, ok := plannerPrioritySignal(meta); ok {
		signals = append(signals, signal)
		signalTypes = append(signalTypes, signal.SignalType)
		weightsByType[signal.SignalType] += signal.Weight
		reasons = append(reasons, signal.Reason)
	}

	score := 0
	distinctSignals := 0
	for signalType, weight := range weightsByType {
		capWeight := signalWeightCaps[signalType]
		if capWeight == 0 {
			capWeight = weight
		}
		if weight > capWeight {
			weight = capWeight
		}
		score += weight
		distinctSignals++
	}
	switch {
	case distinctSignals >= 4:
		score += 18
		reasons = append(reasons, "multiple independent signal types increased confidence")
	case distinctSignals >= 3:
		score += 14
		reasons = append(reasons, "multiple independent signal types increased confidence")
	case distinctSignals >= 2:
		score += 8
		reasons = append(reasons, "multiple independent signal types increased confidence")
	}
	if score > 100 {
		score = 100
	}

	correlated.RuleConfidence = primary.RuleConfidence
	correlated.ConfidenceScore = score
	correlated.Confidence = confidenceLevelForScore(score)
	correlated.SharePriority = meta.SharePriority
	correlated.SharePriorityReason = meta.SharePriorityReason
	correlated.MatchedRuleIDs = uniqueSorted(ruleIDs)
	correlated.MatchedSignalTypes = orderedSignalTypes(uniqueSorted(signalTypes))
	correlated.SupportingSignals = sortSignals(signals)
	correlated.ConfidenceReasons = uniqueSorted(reasons)
	correlated.Tags = uniqueSorted(tags)
	correlated.MatchReason = correlationReason(correlated)
	return correlated
}

func selectPrimaryFinding(group []Finding) Finding {
	best := group[0]
	for _, finding := range group[1:] {
		bestRank := severityRank(best.Severity)
		currRank := severityRank(finding.Severity)
		if currRank > bestRank {
			best = finding
			continue
		}
		if currRank < bestRank {
			continue
		}
		if signalPriority(finding) > signalPriority(best) {
			best = finding
			continue
		}
		if finding.RuleID < best.RuleID {
			best = finding
		}
	}
	return best
}

func signalPriority(f Finding) int {
	if len(f.SupportingSignals) == 0 {
		return 0
	}
	switch f.SupportingSignals[0].SignalType {
	case "content":
		return 3
	case "filename":
		return 2
	case "extension":
		return 1
	default:
		return 0
	}
}

func baseSignalWeight(signalType string) int {
	switch signalType {
	case "content":
		return 32
	case "filename":
		return 18
	case "extension":
		return 10
	case "path":
		return 12
	case "share_priority":
		return 10
	case "planner_priority":
		return 12
	default:
		return 0
	}
}

func confidenceLevelForScore(score int) string {
	switch {
	case score >= 70:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func pathContextSignal(meta FileMetadata) (SupportingSignal, bool) {
	path := strings.ToLower(strings.ReplaceAll(meta.FilePath, `\`, `/`))
	switch {
	case containsAny(path, "/policies/", "policies/", "/preferences/", "preferences/", "/scripts/", "scripts/"):
		return SupportingSignal{
			SignalType: "path",
			Weight:     baseSignalWeight("path"),
			Reason:     "path suggests policy, preference, or script review material",
		}, true
	case containsAny(path, "config", "settings", "secret", "password", "token", "backup", "export", "payroll", "finance", "hr", "customer", "vpn", "admin", "deploy"):
		return SupportingSignal{
			SignalType: "path",
			Weight:     baseSignalWeight("path"),
			Reason:     "path contains high-value keywords associated with sensitive or operational content",
		}, true
	default:
		return SupportingSignal{}, false
	}
}

func sharePrioritySignal(meta FileMetadata) (SupportingSignal, bool) {
	switch {
	case meta.FromSYSVOL:
		return SupportingSignal{
			SignalType: "share_priority",
			Weight:     12,
			Reason:     "SYSVOL is treated as a high-value AD share",
		}, true
	case meta.FromNETLOGON:
		return SupportingSignal{
			SignalType: "share_priority",
			Weight:     10,
			Reason:     "NETLOGON is treated as a high-value AD share",
		}, true
	case meta.SharePriority >= 90:
		return SupportingSignal{
			SignalType: "share_priority",
			Weight:     10,
			Reason:     "share was prioritized highly during planning",
		}, true
	case meta.SharePriority >= 50:
		return SupportingSignal{
			SignalType: "share_priority",
			Weight:     6,
			Reason:     "share was prioritized during planning",
		}, true
	default:
		return SupportingSignal{}, false
	}
}

func plannerPrioritySignal(meta FileMetadata) (SupportingSignal, bool) {
	switch {
	case meta.Priority >= 120:
		return SupportingSignal{
			SignalType: "planner_priority",
			Weight:     14,
			Reason:     "planner marked this file path as critical-priority review material",
		}, true
	case meta.Priority >= 80:
		return SupportingSignal{
			SignalType: "planner_priority",
			Weight:     12,
			Reason:     "planner marked this file path as high-priority review material",
		}, true
	case meta.Priority >= 40:
		return SupportingSignal{
			SignalType: "planner_priority",
			Weight:     6,
			Reason:     "planner marked this file path as relevant review material",
		}, true
	default:
		return SupportingSignal{}, false
	}
}

func correlationReason(f Finding) string {
	if len(f.MatchedSignalTypes) == 0 {
		return f.MatchReason
	}
	return fmt.Sprintf(
		"correlated %d matched rule(s) across %d supporting signal type(s); confidence increased to %s (%d)",
		len(f.MatchedRuleIDs),
		len(f.MatchedSignalTypes),
		f.Confidence,
		f.ConfidenceScore,
	)
}

func orderedSignalTypes(values []string) []string {
	order := map[string]int{
		"content":          0,
		"filename":         1,
		"extension":        2,
		"path":             3,
		"share_priority":   4,
		"planner_priority": 5,
	}
	sort.Slice(values, func(i, j int) bool {
		oi, okI := order[values[i]]
		oj, okJ := order[values[j]]
		if okI && okJ && oi != oj {
			return oi < oj
		}
		if okI != okJ {
			return okI
		}
		return values[i] < values[j]
	})
	return values
}

func sortSignals(signals []SupportingSignal) []SupportingSignal {
	if len(signals) == 0 {
		return nil
	}
	out := append([]SupportingSignal{}, signals...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Weight == out[j].Weight {
			if out[i].SignalType == out[j].SignalType {
				return out[i].RuleID < out[j].RuleID
			}
			return out[i].SignalType < out[j].SignalType
		}
		return out[i].Weight > out[j].Weight
	})
	return out
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

package seed

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"snablr/internal/diff"
	"snablr/internal/scanner"
)

type VerificationFindingSummary struct {
	RuleID      string
	RuleName    string
	Severity    string
	Confidence  string
	Category    string
	SignalType  string
	TriageClass string
	Actionable  bool
	Correlated  bool
	Tags        []string
}

type VerifiedSeedItem struct {
	Entry    SeedManifestEntry
	Findings []VerificationFindingSummary
}

type CoverageSummary struct {
	Category string
	Expected int
	Found    int
	Missed   int
}

type SignalCoverageSummary struct {
	SignalType string
	Expected   int
	Found      int
	Missed     int
}

type ExpectedClassSummary struct {
	ExpectedClass string `json:"expected_class"`
	Planted       int    `json:"planted"`
	Detected      int    `json:"detected"`
	Missed        int    `json:"missed"`
	Matched       int    `json:"matched"`
	Suppressed    int    `json:"suppressed"`
	Downgraded    int    `json:"downgraded"`
	Promoted      int    `json:"promoted"`
	Mismatched    int    `json:"mismatched"`
}

type ClassVerificationItem struct {
	Entry               SeedManifestEntry            `json:"entry"`
	Status              string                       `json:"status"`
	Reason              string                       `json:"reason,omitempty"`
	ObservedTriageClass string                       `json:"observed_triage_class,omitempty"`
	ObservedConfidence  string                       `json:"observed_confidence,omitempty"`
	ObservedActionable  bool                         `json:"observed_actionable,omitempty"`
	ObservedCorrelated  bool                         `json:"observed_correlated,omitempty"`
	Findings            []VerificationFindingSummary `json:"findings,omitempty"`
}

type VerificationReport struct {
	ManifestPath         string
	ResultsPath          string
	ExpectedItems        int
	FoundItems           int
	MissedItems          int
	FillerItems          int
	FillerMatchedItems   int
	FillerMissedItems    int
	UnexpectedFindings   int
	Found                []VerifiedSeedItem
	Missed               []SeedManifestEntry
	Unexpected           []scanner.Finding
	Coverage             []CoverageSummary
	SignalCoverage       []SignalCoverageSummary
	ClassCoverage        []ExpectedClassSummary  `json:"class_coverage,omitempty"`
	SuppressedConfigOnly []ClassVerificationItem `json:"suppressed_config_only,omitempty"`
	PromotedActionable   []ClassVerificationItem `json:"promoted_actionable,omitempty"`
	PromotedCorrelated   []ClassVerificationItem `json:"promoted_correlated,omitempty"`
	ClassMismatches      []ClassVerificationItem `json:"class_mismatches,omitempty"`
}

func Verify(manifestPath, resultsPath string) (VerificationReport, error) {
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return VerificationReport{}, err
	}
	report, err := diff.LoadJSON(resultsPath)
	if err != nil {
		return VerificationReport{}, err
	}

	result := VerificationReport{
		ManifestPath:         manifestPath,
		ResultsPath:          resultsPath,
		Found:                make([]VerifiedSeedItem, 0),
		Missed:               make([]SeedManifestEntry, 0),
		Unexpected:           make([]scanner.Finding, 0),
		Coverage:             make([]CoverageSummary, 0),
		SignalCoverage:       make([]SignalCoverageSummary, 0),
		ClassCoverage:        make([]ExpectedClassSummary, 0),
		SuppressedConfigOnly: make([]ClassVerificationItem, 0),
		PromotedActionable:   make([]ClassVerificationItem, 0),
		PromotedCorrelated:   make([]ClassVerificationItem, 0),
		ClassMismatches:      make([]ClassVerificationItem, 0),
	}

	manifestByKey := make(map[string]SeedManifestEntry, len(manifest.Entries))
	coverage := make(map[string]*CoverageSummary)
	signalCoverage := make(map[string]*SignalCoverageSummary)
	classCoverage := make(map[string]*ExpectedClassSummary)
	for _, entry := range manifest.Entries {
		key := manifestKey(entry)
		if key == "" {
			continue
		}
		manifestByKey[key] = entry
		if !isExpectedVerificationEntry(entry) {
			result.FillerItems++
			continue
		}
		category := normalizedCategory(entry.Category)
		if _, ok := coverage[category]; !ok {
			coverage[category] = &CoverageSummary{Category: category}
		}
		coverage[category].Expected++
		if expectedClass := normalizeExpectedClass(entry.ExpectedClass); expectedClass != "" {
			if _, ok := classCoverage[expectedClass]; !ok {
				classCoverage[expectedClass] = &ExpectedClassSummary{ExpectedClass: expectedClass}
			}
			classCoverage[expectedClass].Planted++
		}
		for _, signalType := range entry.ExpectedSignalTypes {
			normalized := normalizeSignalType(signalType)
			if normalized == "" {
				continue
			}
			if _, ok := signalCoverage[normalized]; !ok {
				signalCoverage[normalized] = &SignalCoverageSummary{SignalType: normalized}
			}
			signalCoverage[normalized].Expected++
		}
	}

	findingsByKey := make(map[string][]scanner.Finding)
	for _, finding := range report.Findings {
		key := findingKey(finding)
		if key == "" {
			continue
		}
		findingsByKey[key] = append(findingsByKey[key], finding)
	}

	for key, entry := range manifestByKey {
		matches := findingsByKey[key]
		if !isExpectedVerificationEntry(entry) {
			if len(matches) > 0 {
				result.FillerMatchedItems++
			} else {
				result.FillerMissedItems++
			}
			continue
		}
		if expectedClass := normalizeExpectedClass(entry.ExpectedClass); expectedClass != "" {
			item := evaluateExpectedClass(entry, matches)
			summary := classCoverage[expectedClass]
			if summary != nil {
				if len(matches) > 0 {
					summary.Detected++
				} else {
					summary.Missed++
				}
				switch item.Status {
				case "suppressed":
					summary.Matched++
					summary.Suppressed++
					if expectedClass == seedClassConfigOnly {
						result.SuppressedConfigOnly = append(result.SuppressedConfigOnly, item)
					}
				case "downgraded":
					summary.Matched++
					summary.Downgraded++
					if expectedClass == seedClassConfigOnly {
						result.SuppressedConfigOnly = append(result.SuppressedConfigOnly, item)
					}
				case "promoted":
					summary.Matched++
					summary.Promoted++
					switch expectedClass {
					case seedClassActionable:
						result.PromotedActionable = append(result.PromotedActionable, item)
					case seedClassCorrelatedHighConfidence:
						result.PromotedCorrelated = append(result.PromotedCorrelated, item)
					}
				case "mismatched":
					summary.Mismatched++
					result.ClassMismatches = append(result.ClassMismatches, item)
				}
			}
		}
		if len(matches) == 0 {
			result.Missed = append(result.Missed, entry)
			coverage[normalizedCategory(entry.Category)].Missed++
			for _, signalType := range entry.ExpectedSignalTypes {
				normalized := normalizeSignalType(signalType)
				if normalized == "" {
					continue
				}
				signalCoverage[normalized].Missed++
			}
			continue
		}

		item := VerifiedSeedItem{
			Entry:    entry,
			Findings: make([]VerificationFindingSummary, 0, len(matches)),
		}
		for _, finding := range matches {
			item.Findings = append(item.Findings, VerificationFindingSummary{
				RuleID:      finding.RuleID,
				RuleName:    finding.RuleName,
				Severity:    finding.Severity,
				Confidence:  finding.Confidence,
				Category:    finding.Category,
				SignalType:  primaryVerificationSignalType(finding),
				TriageClass: finding.TriageClass,
				Actionable:  finding.Actionable,
				Correlated:  finding.Correlated,
				Tags:        append([]string{}, finding.Tags...),
			})
		}
		sort.Slice(item.Findings, func(i, j int) bool {
			if item.Findings[i].Severity == item.Findings[j].Severity {
				return item.Findings[i].RuleID < item.Findings[j].RuleID
			}
			return item.Findings[i].Severity > item.Findings[j].Severity
		})
		result.Found = append(result.Found, item)
		coverage[normalizedCategory(entry.Category)].Found++
		foundSignals := make(map[string]struct{})
		for _, finding := range matches {
			for _, normalized := range allVerificationSignalTypes(finding) {
				foundSignals[normalized] = struct{}{}
			}
		}
		for _, signalType := range entry.ExpectedSignalTypes {
			normalized := normalizeSignalType(signalType)
			if normalized == "" {
				continue
			}
			if _, ok := foundSignals[normalized]; ok {
				signalCoverage[normalized].Found++
			} else {
				signalCoverage[normalized].Missed++
			}
		}
	}

	for key, findings := range findingsByKey {
		if _, ok := manifestByKey[key]; ok {
			continue
		}
		result.Unexpected = append(result.Unexpected, findings...)
	}

	for _, summary := range coverage {
		result.Coverage = append(result.Coverage, *summary)
	}
	for _, summary := range signalCoverage {
		result.SignalCoverage = append(result.SignalCoverage, *summary)
	}
	for _, summary := range classCoverage {
		result.ClassCoverage = append(result.ClassCoverage, *summary)
	}

	sort.Slice(result.Found, func(i, j int) bool {
		if result.Found[i].Entry.Category == result.Found[j].Entry.Category {
			if result.Found[i].Entry.Host == result.Found[j].Entry.Host {
				if result.Found[i].Entry.Share == result.Found[j].Entry.Share {
					return result.Found[i].Entry.Path < result.Found[j].Entry.Path
				}
				return result.Found[i].Entry.Share < result.Found[j].Entry.Share
			}
			return result.Found[i].Entry.Host < result.Found[j].Entry.Host
		}
		return result.Found[i].Entry.Category < result.Found[j].Entry.Category
	})
	sort.Slice(result.Missed, func(i, j int) bool {
		if result.Missed[i].Category == result.Missed[j].Category {
			if result.Missed[i].Host == result.Missed[j].Host {
				if result.Missed[i].Share == result.Missed[j].Share {
					return result.Missed[i].Path < result.Missed[j].Path
				}
				return result.Missed[i].Share < result.Missed[j].Share
			}
			return result.Missed[i].Host < result.Missed[j].Host
		}
		return result.Missed[i].Category < result.Missed[j].Category
	})
	sort.Slice(result.Unexpected, func(i, j int) bool {
		left := findingKey(result.Unexpected[i])
		right := findingKey(result.Unexpected[j])
		return left < right
	})
	sort.Slice(result.Coverage, func(i, j int) bool {
		return result.Coverage[i].Category < result.Coverage[j].Category
	})
	sort.Slice(result.SignalCoverage, func(i, j int) bool {
		return result.SignalCoverage[i].SignalType < result.SignalCoverage[j].SignalType
	})
	sort.Slice(result.ClassCoverage, func(i, j int) bool {
		return result.ClassCoverage[i].ExpectedClass < result.ClassCoverage[j].ExpectedClass
	})
	sortClassVerificationItems(result.SuppressedConfigOnly)
	sortClassVerificationItems(result.PromotedActionable)
	sortClassVerificationItems(result.PromotedCorrelated)
	sortClassVerificationItems(result.ClassMismatches)

	result.FoundItems = len(result.Found)
	result.MissedItems = len(result.Missed)
	result.ExpectedItems = result.FoundItems + result.MissedItems
	result.UnexpectedFindings = len(result.Unexpected)
	return result, nil
}

func PrintVerificationReport(report VerificationReport) {
	fmt.Println("Snablr Seeder Verification")
	fmt.Printf("Expected items: %d\n", report.ExpectedItems)
	fmt.Printf("Expected items found: %d\n", report.FoundItems)
	fmt.Printf("Expected items missed: %d\n", report.MissedItems)
	if report.FillerItems > 0 {
		fmt.Printf("Filler/noise items: %d (%d matched, %d not matched)\n", report.FillerItems, report.FillerMatchedItems, report.FillerMissedItems)
	}
	fmt.Printf("Unexpected findings: %d\n", report.UnexpectedFindings)

	if len(report.Coverage) > 0 {
		fmt.Println("\nCoverage by category:")
		for _, category := range report.Coverage {
			fmt.Printf("- %s: found %d/%d missed %d\n", category.Category, category.Found, category.Expected, category.Missed)
		}
	}
	if len(report.SignalCoverage) > 0 {
		fmt.Println("\nCoverage by signal type:")
		for _, signal := range report.SignalCoverage {
			fmt.Printf("- %s: found %d/%d missed %d\n", signal.SignalType, signal.Found, signal.Expected, signal.Missed)
		}
	}
	if len(report.ClassCoverage) > 0 {
		fmt.Println("\nSeeded class behavior:")
		for _, summary := range report.ClassCoverage {
			fmt.Printf("- %s: planted %d detected %d missed %d matched %d suppressed %d downgraded %d promoted %d mismatched %d\n",
				summary.ExpectedClass, summary.Planted, summary.Detected, summary.Missed, summary.Matched, summary.Suppressed, summary.Downgraded, summary.Promoted, summary.Mismatched)
		}
	}
	if len(report.SuppressedConfigOnly) > 0 {
		fmt.Println("\nConfig-only handled safely:")
		for _, item := range report.SuppressedConfigOnly {
			fmt.Printf("- [%s] %s/%s/%s", item.Status, item.Entry.Host, item.Entry.Share, item.Entry.Path)
			if item.ObservedTriageClass != "" || item.ObservedConfidence != "" {
				fmt.Printf(" observed=%s confidence=%s correlated=%t", valueOrDash(item.ObservedTriageClass), valueOrDash(item.ObservedConfidence), item.ObservedCorrelated)
			}
			if item.Reason != "" {
				fmt.Printf(" reason=%s", item.Reason)
			}
			fmt.Println()
		}
	}
	if len(report.PromotedActionable) > 0 {
		fmt.Println("\nActionable findings promoted:")
		for _, item := range report.PromotedActionable {
			fmt.Printf("- %s/%s/%s observed=%s confidence=%s correlated=%t\n",
				item.Entry.Host, item.Entry.Share, item.Entry.Path, valueOrDash(item.ObservedTriageClass), valueOrDash(item.ObservedConfidence), item.ObservedCorrelated)
		}
	}
	if len(report.PromotedCorrelated) > 0 {
		fmt.Println("\nCorrelated high-confidence findings promoted:")
		for _, item := range report.PromotedCorrelated {
			fmt.Printf("- %s/%s/%s observed=%s confidence=%s correlated=%t\n",
				item.Entry.Host, item.Entry.Share, item.Entry.Path, valueOrDash(item.ObservedTriageClass), valueOrDash(item.ObservedConfidence), item.ObservedCorrelated)
		}
	}
	if len(report.ClassMismatches) > 0 {
		fmt.Println("\nClass mismatches:")
		for _, item := range report.ClassMismatches {
			fmt.Printf("- [%s] %s/%s/%s observed=%s confidence=%s correlated=%t reason=%s\n",
				valueOrDash(item.Entry.ExpectedClass), item.Entry.Host, item.Entry.Share, item.Entry.Path,
				valueOrDash(item.ObservedTriageClass), valueOrDash(item.ObservedConfidence), item.ObservedCorrelated, item.Reason)
		}
	}

	if len(report.Missed) > 0 {
		fmt.Println("\nMissed expected items:")
		for _, entry := range report.Missed {
			fmt.Printf("- [%s] %s/%s/%s\n", entry.Category, entry.Host, entry.Share, entry.Path)
		}
	}

	if len(report.Unexpected) > 0 {
		fmt.Println("\nUnexpected findings:")
		for _, finding := range report.Unexpected {
			fmt.Printf("- [%s] %s %s/%s/%s\n", finding.Severity, finding.RuleID, valueOrDash(finding.Host), valueOrDash(finding.Share), finding.FilePath)
		}
	}
}

func manifestKey(entry SeedManifestEntry) string {
	host := normalizeVerifyValue(entry.Host)
	share := normalizeVerifyValue(entry.Share)
	path := normalizeVerifyPath(entry.Path)
	if host == "" || share == "" || path == "" {
		return ""
	}
	return host + "::" + share + "::" + path
}

func findingKey(finding scanner.Finding) string {
	host := normalizeVerifyValue(finding.Host)
	share := normalizeVerifyValue(finding.Share)
	path := normalizeVerifyPath(finding.FilePath)
	if host == "" || share == "" || path == "" {
		return ""
	}
	return host + "::" + share + "::" + path
}

func normalizeVerifyValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeVerifyPath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimPrefix(value, "/")
	if value == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(value))
}

func normalizedCategory(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "uncategorized"
	}
	return value
}

func normalizeSignalType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return value
}

func primaryVerificationSignalType(finding scanner.Finding) string {
	signals := allVerificationSignalTypes(finding)
	if len(signals) > 0 {
		return signals[0]
	}
	if strings.TrimSpace(finding.SignalType) != "" {
		return finding.SignalType
	}
	if len(finding.MatchedSignalTypes) > 0 {
		return finding.MatchedSignalTypes[0]
	}
	return ""
}

func allVerificationSignalTypes(finding scanner.Finding) []string {
	values := make([]string, 0, 1+len(finding.MatchedSignalTypes)+len(finding.SupportingSignals))
	if normalized := normalizeSignalType(finding.SignalType); normalized != "" {
		values = append(values, normalized)
	}
	for _, signalType := range finding.MatchedSignalTypes {
		if normalized := normalizeSignalType(signalType); normalized != "" {
			values = append(values, normalized)
		}
	}
	for _, signal := range finding.SupportingSignals {
		if normalized := normalizeSignalType(signal.SignalType); normalized != "" {
			values = append(values, normalized)
		}
	}
	return uniqueNormalizedValues(values)
}

func uniqueNormalizedValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeSignalType(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func isExpectedVerificationEntry(entry SeedManifestEntry) bool {
	intendedAs := strings.TrimSpace(strings.ToLower(entry.IntendedAs))
	return intendedAs == "" || intendedAs != "filler/noise"
}

type observedFinding struct {
	TriageClass string
	Confidence  string
	Actionable  bool
	Correlated  bool
	Findings    []VerificationFindingSummary
}

func evaluateExpectedClass(entry SeedManifestEntry, matches []scanner.Finding) ClassVerificationItem {
	item := ClassVerificationItem{
		Entry: entry,
	}
	expectedClass := normalizeExpectedClass(entry.ExpectedClass)
	if expectedClass == "" {
		return item
	}
	if len(matches) == 0 {
		switch expectedClass {
		case seedClassConfigOnly:
			item.Status = "suppressed"
			item.Reason = "no finding surfaced for a config-only seeded artifact"
		default:
			item.Status = "mismatched"
			item.Reason = "no finding surfaced for this seeded artifact"
		}
		return item
	}

	observed := summarizeObservedFindings(matches)
	item.ObservedTriageClass = observed.TriageClass
	item.ObservedConfidence = observed.Confidence
	item.ObservedActionable = observed.Actionable
	item.ObservedCorrelated = observed.Correlated
	item.Findings = observed.Findings

	switch expectedClass {
	case seedClassConfigOnly:
		if isLowValueObserved(observed) {
			item.Status = "downgraded"
			item.Reason = "generic configuration stayed low-visibility"
			return item
		}
		item.Status = "mismatched"
		item.Reason = "config-only artifact was promoted more strongly than expected"
	case seedClassWeakReview:
		if isLowValueObserved(observed) {
			item.Status = "downgraded"
			item.Reason = "weak review candidate remained low-visibility"
			return item
		}
		item.Status = "mismatched"
		item.Reason = "weak review candidate was promoted too aggressively"
	case seedClassActionable:
		if matchesExpectedPromotion(observed, entry, false) {
			item.Status = "promoted"
			item.Reason = "actionable artifact surfaced clearly"
			return item
		}
		item.Status = "mismatched"
		item.Reason = "actionable artifact did not surface strongly enough"
	case seedClassCorrelatedHighConfidence:
		if matchesExpectedPromotion(observed, entry, true) {
			item.Status = "promoted"
			item.Reason = "correlated multi-signal artifact surfaced as intended"
			return item
		}
		item.Status = "mismatched"
		item.Reason = "correlated high-confidence artifact did not surface strongly enough"
	default:
		item.Status = "mismatched"
		item.Reason = "unsupported expected class"
	}

	return item
}

func summarizeObservedFindings(matches []scanner.Finding) observedFinding {
	bestIdx := 0
	bestScore := -1
	summaries := make([]VerificationFindingSummary, 0, len(matches))
	for idx, finding := range matches {
		summaries = append(summaries, VerificationFindingSummary{
			RuleID:      finding.RuleID,
			RuleName:    finding.RuleName,
			Severity:    finding.Severity,
			Confidence:  finding.Confidence,
			Category:    finding.Category,
			SignalType:  primaryVerificationSignalType(finding),
			TriageClass: finding.TriageClass,
			Actionable:  finding.Actionable,
			Correlated:  finding.Correlated,
			Tags:        append([]string{}, finding.Tags...),
		})
		score := observedFindingScore(finding)
		if score > bestScore {
			bestScore = score
			bestIdx = idx
		}
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Correlated != summaries[j].Correlated {
			return summaries[i].Correlated
		}
		if confidenceRank(summaries[i].Confidence) != confidenceRank(summaries[j].Confidence) {
			return confidenceRank(summaries[i].Confidence) > confidenceRank(summaries[j].Confidence)
		}
		if severityRank(summaries[i].Severity) != severityRank(summaries[j].Severity) {
			return severityRank(summaries[i].Severity) > severityRank(summaries[j].Severity)
		}
		return summaries[i].RuleID < summaries[j].RuleID
	})

	best := matches[bestIdx]
	return observedFinding{
		TriageClass: strings.TrimSpace(best.TriageClass),
		Confidence:  strings.TrimSpace(best.Confidence),
		Actionable:  best.Actionable,
		Correlated:  best.Correlated,
		Findings:    summaries,
	}
}

func observedFindingScore(finding scanner.Finding) int {
	score := 0
	if finding.Correlated {
		score += 200
	}
	if finding.Actionable {
		score += 100
	}
	switch strings.ToLower(strings.TrimSpace(finding.TriageClass)) {
	case seedTriageActionable:
		score += 80
	case seedTriageWeakReview:
		score += 40
	case seedTriageConfigOnly:
		score += 10
	}
	score += confidenceRank(finding.Confidence) * 10
	score += severityRank(finding.Severity)
	score += len(finding.MatchedRuleIDs)
	return score
}

func matchesExpectedPromotion(observed observedFinding, entry SeedManifestEntry, requireCorrelated bool) bool {
	if !observed.Actionable && !strings.EqualFold(observed.TriageClass, seedTriageActionable) {
		return false
	}
	minConfidence := confidenceRank(entry.ExpectedConfidence)
	if minConfidence == 0 {
		minConfidence = confidenceRank("medium")
	}
	if confidenceRank(observed.Confidence) < minConfidence {
		return false
	}
	if requireCorrelated || entry.ExpectedCorrelated {
		return observed.Correlated
	}
	return true
}

func isLowValueObserved(observed observedFinding) bool {
	switch strings.ToLower(strings.TrimSpace(observed.TriageClass)) {
	case seedTriageConfigOnly, seedTriageWeakReview:
		return true
	}
	return !observed.Actionable && !observed.Correlated && confidenceRank(observed.Confidence) <= confidenceRank("medium")
}

func normalizeExpectedClass(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortClassVerificationItems(items []ClassVerificationItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Entry.Category == items[j].Entry.Category {
			if items[i].Entry.Host == items[j].Entry.Host {
				if items[i].Entry.Share == items[j].Entry.Share {
					return items[i].Entry.Path < items[j].Entry.Path
				}
				return items[i].Entry.Share < items[j].Entry.Share
			}
			return items[i].Entry.Host < items[j].Entry.Host
		}
		return items[i].Entry.Category < items[j].Entry.Category
	})
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
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

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
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

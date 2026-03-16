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
	RuleID     string
	RuleName   string
	Severity   string
	Category   string
	SignalType string
	Tags       []string
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

type VerificationReport struct {
	ManifestPath       string
	ResultsPath        string
	ExpectedItems      int
	FoundItems         int
	MissedItems        int
	FillerItems        int
	FillerMatchedItems int
	FillerMissedItems  int
	UnexpectedFindings int
	Found              []VerifiedSeedItem
	Missed             []SeedManifestEntry
	Unexpected         []scanner.Finding
	Coverage           []CoverageSummary
	SignalCoverage     []SignalCoverageSummary
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
		ManifestPath:   manifestPath,
		ResultsPath:    resultsPath,
		Found:          make([]VerifiedSeedItem, 0),
		Missed:         make([]SeedManifestEntry, 0),
		Unexpected:     make([]scanner.Finding, 0),
		Coverage:       make([]CoverageSummary, 0),
		SignalCoverage: make([]SignalCoverageSummary, 0),
	}

	manifestByKey := make(map[string]SeedManifestEntry, len(manifest.Entries))
	coverage := make(map[string]*CoverageSummary)
	signalCoverage := make(map[string]*SignalCoverageSummary)
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
				RuleID:     finding.RuleID,
				RuleName:   finding.RuleName,
				Severity:   finding.Severity,
				Category:   finding.Category,
				SignalType: primaryVerificationSignalType(finding),
				Tags:       append([]string{}, finding.Tags...),
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

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

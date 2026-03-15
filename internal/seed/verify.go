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
	RuleID   string
	RuleName string
	Severity string
	Category string
	Tags     []string
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

type VerificationReport struct {
	ManifestPath       string
	ResultsPath        string
	ExpectedItems      int
	FoundItems         int
	MissedItems        int
	UnexpectedFindings int
	Found              []VerifiedSeedItem
	Missed             []SeedManifestEntry
	Unexpected         []scanner.Finding
	Coverage           []CoverageSummary
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
		ManifestPath: manifestPath,
		ResultsPath:  resultsPath,
		Found:        make([]VerifiedSeedItem, 0),
		Missed:       make([]SeedManifestEntry, 0),
		Unexpected:   make([]scanner.Finding, 0),
		Coverage:     make([]CoverageSummary, 0),
	}

	manifestByKey := make(map[string]SeedManifestEntry, len(manifest.Entries))
	coverage := make(map[string]*CoverageSummary)
	for _, entry := range manifest.Entries {
		key := manifestKey(entry)
		if key == "" {
			continue
		}
		manifestByKey[key] = entry
		category := normalizedCategory(entry.Category)
		if _, ok := coverage[category]; !ok {
			coverage[category] = &CoverageSummary{Category: category}
		}
		coverage[category].Expected++
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
		if len(matches) == 0 {
			result.Missed = append(result.Missed, entry)
			coverage[normalizedCategory(entry.Category)].Missed++
			continue
		}

		item := VerifiedSeedItem{
			Entry:    entry,
			Findings: make([]VerificationFindingSummary, 0, len(matches)),
		}
		for _, finding := range matches {
			item.Findings = append(item.Findings, VerificationFindingSummary{
				RuleID:   finding.RuleID,
				RuleName: finding.RuleName,
				Severity: finding.Severity,
				Category: finding.Category,
				Tags:     append([]string{}, finding.Tags...),
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

	result.ExpectedItems = len(manifestByKey)
	result.FoundItems = len(result.Found)
	result.MissedItems = len(result.Missed)
	result.UnexpectedFindings = len(result.Unexpected)
	return result, nil
}

func PrintVerificationReport(report VerificationReport) {
	fmt.Println("Snablr Seeder Verification")
	fmt.Printf("Expected items: %d\n", report.ExpectedItems)
	fmt.Printf("Expected items found: %d\n", report.FoundItems)
	fmt.Printf("Expected items missed: %d\n", report.MissedItems)
	fmt.Printf("Unexpected findings: %d\n", report.UnexpectedFindings)

	if len(report.Coverage) > 0 {
		fmt.Println("\nCoverage by category:")
		for _, category := range report.Coverage {
			fmt.Printf("- %s: found %d/%d missed %d\n", category.Category, category.Found, category.Expected, category.Missed)
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

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

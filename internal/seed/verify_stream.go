package seed

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/scanner"
)

// FindingIterator supplies persisted findings without transferring ownership
// of a complete in-memory result population to the verifier.
type FindingIterator func(func(scanner.Finding) error) error

// VerifyFindingIteratorSummary verifies the fields consumed by report
// validation summaries. Observations are indexed in a temporary SQLite file;
// only the observations for the manifest entry currently being evaluated are
// decoded. Detailed Found/Unexpected payload lists remain available through
// VerifyFindings for small offline callers, but are intentionally not built by
// this production-oriented path.
func VerifyFindingIteratorSummary(manifestPath string, iterate FindingIterator) (VerificationReport, error) {
	if iterate == nil {
		return VerificationReport{}, fmt.Errorf("finding iterator is nil")
	}
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return VerificationReport{}, err
	}
	file, err := os.CreateTemp("", "snablr-validation-*.db")
	if err != nil {
		return VerificationReport{}, err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return VerificationReport{}, err
	}
	defer os.Remove(path)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return VerificationReport{}, err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE observations (finding_key TEXT NOT NULL, sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL); CREATE INDEX observations_key ON observations(finding_key)`); err != nil {
		return VerificationReport{}, err
	}
	if err := iterate(func(finding scanner.Finding) error {
		key := findingKey(finding)
		if key == "" {
			return nil
		}
		payload, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		_, err = db.Exec(`INSERT INTO observations(finding_key,payload) VALUES(?,?)`, key, payload)
		return err
	}); err != nil {
		return VerificationReport{}, err
	}

	result := VerificationReport{ManifestPath: manifestPath, Coverage: []CoverageSummary{}, SignalCoverage: []SignalCoverageSummary{}, ClassCoverage: []ExpectedClassSummary{}, SuppressedConfigOnly: []ClassVerificationItem{}, PromotedActionable: []ClassVerificationItem{}, PromotedCorrelated: []ClassVerificationItem{}, ClassMismatches: []ClassVerificationItem{}}
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
			if isFillerVerificationEntry(entry) {
				result.FillerItems++
			}
			continue
		}
		category := normalizedCategory(entry.Category)
		if coverage[category] == nil {
			coverage[category] = &CoverageSummary{Category: category}
		}
		coverage[category].Expected++
		if expectedClass := normalizeExpectedClass(entry.ExpectedClass); expectedClass != "" {
			if classCoverage[expectedClass] == nil {
				classCoverage[expectedClass] = &ExpectedClassSummary{ExpectedClass: expectedClass}
			}
			classCoverage[expectedClass].Planted++
		}
		for _, signal := range entry.ExpectedSignalTypes {
			signal = normalizeSignalType(signal)
			if signal == "" {
				continue
			}
			if signalCoverage[signal] == nil {
				signalCoverage[signal] = &SignalCoverageSummary{SignalType: signal}
			}
			signalCoverage[signal].Expected++
		}
	}

	for key, entry := range manifestByKey {
		matchCount, observed, foundSignals, err := streamValidationGroup(db, key)
		if err != nil {
			return VerificationReport{}, err
		}
		if !isExpectedVerificationEntry(entry) {
			if isFillerVerificationEntry(entry) {
				if matchCount > 0 {
					result.FillerMatchedItems++
				} else {
					result.FillerMissedItems++
				}
			}
			continue
		}
		category := normalizedCategory(entry.Category)
		if expectedClass := normalizeExpectedClass(entry.ExpectedClass); expectedClass != "" {
			item := evaluateExpectedClassObserved(entry, matchCount, observed)
			summary := classCoverage[expectedClass]
			if matchCount > 0 {
				summary.Detected++
			} else {
				summary.Missed++
			}
			switch item.Status {
			case "matched":
				summary.Matched++
			case "suppressed", "downgraded":
				summary.Matched++
				if item.Status == "suppressed" {
					summary.Suppressed++
				} else {
					summary.Downgraded++
				}
				if expectedClass == seedClassConfigOnly {
					result.SuppressedConfigOnly = append(result.SuppressedConfigOnly, compactClassItem(item))
				}
			case "promoted":
				summary.Matched++
				summary.Promoted++
				if expectedClass == seedClassCorrelatedHighConfidence {
					result.PromotedCorrelated = append(result.PromotedCorrelated, compactClassItem(item))
				} else if expectedClass == seedClassCredential || expectedClass == seedClassActionable {
					result.PromotedActionable = append(result.PromotedActionable, compactClassItem(item))
				}
			case "mismatched":
				summary.Mismatched++
				result.ClassMismatches = append(result.ClassMismatches, compactClassItem(item))
			}
		}
		if matchCount == 0 {
			result.MissedItems++
			result.Missed = append(result.Missed, entry)
			coverage[category].Missed++
		} else {
			result.FoundItems++
			coverage[category].Found++
		}
		for _, signal := range entry.ExpectedSignalTypes {
			signal = normalizeSignalType(signal)
			if signal == "" {
				continue
			}
			if _, ok := foundSignals[signal]; ok {
				signalCoverage[signal].Found++
			} else {
				signalCoverage[signal].Missed++
			}
		}
	}

	rows, err := db.Query(`SELECT finding_key, COUNT(*) FROM observations GROUP BY finding_key`)
	if err != nil {
		return VerificationReport{}, err
	}
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			_ = rows.Close()
			return VerificationReport{}, err
		}
		if _, expected := manifestByKey[key]; !expected {
			result.UnexpectedFindings += count
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return VerificationReport{}, err
	}
	if err := rows.Close(); err != nil {
		return VerificationReport{}, err
	}
	for _, item := range coverage {
		result.Coverage = append(result.Coverage, *item)
	}
	for _, item := range signalCoverage {
		result.SignalCoverage = append(result.SignalCoverage, *item)
	}
	for _, item := range classCoverage {
		result.ClassCoverage = append(result.ClassCoverage, *item)
	}
	result.ExpectedItems = result.FoundItems + result.MissedItems
	sort.Slice(result.Coverage, func(i, j int) bool { return result.Coverage[i].Category < result.Coverage[j].Category })
	sort.Slice(result.SignalCoverage, func(i, j int) bool { return result.SignalCoverage[i].SignalType < result.SignalCoverage[j].SignalType })
	sort.Slice(result.ClassCoverage, func(i, j int) bool {
		return result.ClassCoverage[i].ExpectedClass < result.ClassCoverage[j].ExpectedClass
	})
	sort.Slice(result.Missed, func(i, j int) bool { return manifestKey(result.Missed[i]) < manifestKey(result.Missed[j]) })
	sortClassVerificationItems(result.SuppressedConfigOnly)
	sortClassVerificationItems(result.PromotedActionable)
	sortClassVerificationItems(result.PromotedCorrelated)
	sortClassVerificationItems(result.ClassMismatches)
	return result, nil
}

func streamValidationGroup(db *sql.DB, key string) (int, observedFinding, map[string]struct{}, error) {
	rows, err := db.Query(`SELECT payload FROM observations WHERE finding_key=? ORDER BY sequence`, key)
	if err != nil {
		return 0, observedFinding{}, nil, err
	}
	defer rows.Close()
	count := 0
	bestScore := -1
	var best scanner.Finding
	foundSignals := make(map[string]struct{})
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return 0, observedFinding{}, nil, err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return 0, observedFinding{}, nil, err
		}
		count++
		for _, signal := range allVerificationSignalTypes(finding) {
			foundSignals[signal] = struct{}{}
		}
		if score := observedFindingScore(finding); score > bestScore {
			bestScore = score
			best = finding
		}
	}
	if err := rows.Err(); err != nil {
		return 0, observedFinding{}, nil, err
	}
	if count == 0 {
		return 0, observedFinding{}, foundSignals, nil
	}
	return count, observedFinding{TriageClass: strings.TrimSpace(best.TriageClass), Confidence: strings.TrimSpace(best.Confidence), Actionable: best.Actionable, Correlated: best.Correlated}, foundSignals, nil
}

func evaluateExpectedClassObserved(entry SeedManifestEntry, count int, observed observedFinding) ClassVerificationItem {
	item := ClassVerificationItem{Entry: entry, ObservedTriageClass: observed.TriageClass, ObservedConfidence: observed.Confidence, ObservedActionable: observed.Actionable, ObservedCorrelated: observed.Correlated}
	expectedClass := normalizeExpectedClass(entry.ExpectedClass)
	if expectedClass == "" {
		return item
	}
	if count == 0 {
		if expectedClass == seedClassConfigOnly {
			item.Status = "suppressed"
			item.Reason = "no finding surfaced for a config-only seeded artifact"
		} else {
			item.Status = "mismatched"
			item.Reason = "no finding surfaced for this seeded artifact"
		}
		return item
	}
	switch expectedClass {
	case seedClassCredential:
		item.Status = "matched"
		item.Reason = "credential artifact was observed; promotion is evaluated separately"
	case seedClassConfigOnly:
		if isLowValueObserved(observed) {
			item.Status = "downgraded"
			item.Reason = "generic configuration stayed low-visibility"
		} else {
			item.Status = "mismatched"
			item.Reason = "config-only artifact was promoted more strongly than expected"
		}
	case seedClassWeakReview:
		if isLowValueObserved(observed) {
			item.Status = "downgraded"
			item.Reason = "weak review candidate remained low-visibility"
		} else {
			item.Status = "mismatched"
			item.Reason = "weak review candidate was promoted too aggressively"
		}
	case seedClassActionable:
		if matchesExpectedPromotion(observed, entry, false) {
			item.Status = "promoted"
			item.Reason = "actionable artifact surfaced clearly"
		} else {
			item.Status = "mismatched"
			item.Reason = "actionable artifact did not surface strongly enough"
		}
	case seedClassCorrelatedHighConfidence:
		if matchesExpectedPromotion(observed, entry, true) {
			item.Status = "promoted"
			item.Reason = "correlated multi-signal artifact surfaced as intended"
		} else {
			item.Status = "mismatched"
			item.Reason = "correlated high-confidence artifact did not surface strongly enough"
		}
	default:
		item.Status = "mismatched"
		item.Reason = "unsupported expected class"
	}
	return item
}

func compactClassItem(item ClassVerificationItem) ClassVerificationItem {
	item.Findings = nil
	return item
}

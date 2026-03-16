package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"snablr/internal/benchmark"
	"snablr/internal/scanner"
)

func LoadLabels(path string) (LabelsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LabelsFile{}, fmt.Errorf("read labels %s: %w", path, err)
	}

	var labels LabelsFile
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := json.Unmarshal(data, &labels); err != nil {
			return LabelsFile{}, fmt.Errorf("parse labels %s: %w", path, err)
		}
		return labels, nil
	}
	if err := yaml.Unmarshal(data, &labels); err != nil {
		return LabelsFile{}, fmt.Errorf("parse labels %s: %w", path, err)
	}
	return labels, nil
}

func Run(ctx context.Context, cfg benchmark.Config, labelsPath string) (Report, error) {
	if strings.TrimSpace(labelsPath) == "" {
		return Report{}, fmt.Errorf("labels path is required")
	}

	startedAt := time.Now().UTC()
	run, err := benchmark.Run(ctx, cfg)
	if err != nil {
		return Report{}, err
	}
	labels, err := LoadLabels(labelsPath)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Name:      strings.TrimSpace(labels.Name),
		Dataset:   run.Dataset,
		Labels:    labelsPath,
		StartedAt: startedAt,
		EndedAt:   time.Now().UTC(),
		Benchmark: run,
	}
	evaluate(&report, labels)
	return report, nil
}

func WriteJSON(report Report, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("evaluation output path cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func evaluate(report *Report, labels LabelsFile) {
	if report == nil {
		return
	}

	actualByKey := make(map[string][]scanner.Finding)
	matchedKeys := make(map[string]int)
	for _, finding := range report.Benchmark.Findings {
		key := findingKey(relativeFindingPath(report.Dataset, finding.FilePath), finding.Category)
		actualByKey[key] = append(actualByKey[key], finding)
	}

	for _, expected := range labels.Expectations {
		path := normalizeEvalPath(expected.Path)
		key := findingKey(path, expected.Category)
		candidates := actualByKey[key]
		if len(candidates) == 0 {
			report.Missed = append(report.Missed, MissedExpectation{
				Expectation: expected,
				Reason:      "no finding matched the expected path and category",
			})
			continue
		}

		matched := selectExpectedFinding(expected, candidates)
		if matched == nil {
			report.Missed = append(report.Missed, MissedExpectation{
				Expectation: expected,
				Reason:      "findings existed for the path/category, but not for the expected rule IDs",
			})
			continue
		}

		warnings := expectationWarnings(expected, *matched)
		report.Matched = append(report.Matched, MatchedExpectation{
			Expectation: expected,
			Finding:     *matched,
			Warnings:    warnings,
		})
		matchedKeys[key]++
		report.Summary.WarningsTotal += len(warnings)
	}

	for key, findings := range actualByKey {
		if len(findings) > 1 {
			parts := strings.SplitN(key, "::", 2)
			report.Duplicates = append(report.Duplicates, DuplicateFinding{
				Path:     parts[0],
				Category: parts[1],
				Findings: append([]scanner.Finding{}, findings...),
			})
		}
		if matchedKeys[key] > 0 {
			continue
		}
		for _, finding := range findings {
			report.Noisy = append(report.Noisy, NoisyFinding{
				Path:     relativeFindingPath(report.Dataset, finding.FilePath),
				Category: finding.Category,
				Finding:  finding,
			})
		}
	}

	report.Summary.ExpectedTotal = len(labels.Expectations)
	report.Summary.MatchedTotal = len(report.Matched)
	report.Summary.MissedTotal = len(report.Missed)
	report.Summary.NoisyTotal = len(report.Noisy)
	report.Summary.DuplicateTotal = len(report.Duplicates)
	if denom := report.Summary.MatchedTotal + report.Summary.NoisyTotal; denom > 0 {
		report.Summary.PrecisionLike = float64(report.Summary.MatchedTotal) / float64(denom)
	}
	if report.Summary.ExpectedTotal > 0 {
		report.Summary.RecallLike = float64(report.Summary.MatchedTotal) / float64(report.Summary.ExpectedTotal)
	}
	report.NoisyRuleCandidates = toRuleCandidates(countNoisy(report.Noisy))
	report.MissedRuleCandidates = toRuleCandidates(countMissed(report.Missed))

	sort.Slice(report.Matched, func(i, j int) bool {
		if report.Matched[i].Expectation.Path == report.Matched[j].Expectation.Path {
			return report.Matched[i].Expectation.Category < report.Matched[j].Expectation.Category
		}
		return report.Matched[i].Expectation.Path < report.Matched[j].Expectation.Path
	})
	sort.Slice(report.Missed, func(i, j int) bool {
		if report.Missed[i].Expectation.Path == report.Missed[j].Expectation.Path {
			return report.Missed[i].Expectation.Category < report.Missed[j].Expectation.Category
		}
		return report.Missed[i].Expectation.Path < report.Missed[j].Expectation.Path
	})
	sort.Slice(report.Noisy, func(i, j int) bool {
		if report.Noisy[i].Path == report.Noisy[j].Path {
			return report.Noisy[i].Category < report.Noisy[j].Category
		}
		return report.Noisy[i].Path < report.Noisy[j].Path
	})
}

func selectExpectedFinding(expected Expectation, findings []scanner.Finding) *scanner.Finding {
	if len(findings) == 0 {
		return nil
	}
	if len(expected.RuleIDs) == 0 {
		finding := findings[0]
		return &finding
	}
	expectedRules := make(map[string]struct{}, len(expected.RuleIDs))
	for _, ruleID := range expected.RuleIDs {
		expectedRules[strings.TrimSpace(ruleID)] = struct{}{}
	}
	for _, finding := range findings {
		if _, ok := expectedRules[finding.RuleID]; ok {
			copyFinding := finding
			return &copyFinding
		}
		for _, matchedRuleID := range finding.MatchedRuleIDs {
			if _, ok := expectedRules[strings.TrimSpace(matchedRuleID)]; ok {
				copyFinding := finding
				return &copyFinding
			}
		}
	}
	return nil
}

func expectationWarnings(expected Expectation, finding scanner.Finding) []string {
	var warnings []string
	if expected.MinimumSeverity != "" && severityRank(finding.Severity) < severityRank(expected.MinimumSeverity) {
		warnings = append(warnings, fmt.Sprintf("severity %s is below expected minimum %s", finding.Severity, expected.MinimumSeverity))
	}
	if expected.MinimumConfidence != "" && confidenceRank(finding.Confidence) < confidenceRank(expected.MinimumConfidence) {
		warnings = append(warnings, fmt.Sprintf("confidence %s is below expected minimum %s", finding.Confidence, expected.MinimumConfidence))
	}
	return warnings
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

func countNoisy(noisy []NoisyFinding) map[string]int {
	counts := make(map[string]int)
	for _, finding := range noisy {
		ruleID := strings.TrimSpace(finding.Finding.RuleID)
		if ruleID == "" {
			ruleID = "unknown-rule"
		}
		counts[ruleID]++
	}
	return counts
}

func countMissed(missed []MissedExpectation) map[string]int {
	counts := make(map[string]int)
	for _, miss := range missed {
		if len(miss.Expectation.RuleIDs) > 0 {
			for _, ruleID := range miss.Expectation.RuleIDs {
				ruleID = strings.TrimSpace(ruleID)
				if ruleID == "" {
					continue
				}
				counts[ruleID]++
			}
			continue
		}
		name := "category:" + strings.TrimSpace(miss.Expectation.Category)
		counts[name]++
	}
	return counts
}

func toRuleCandidates(counts map[string]int) []RuleCandidate {
	if len(counts) == 0 {
		return nil
	}
	out := make([]RuleCandidate, 0, len(counts))
	for name, count := range counts {
		out = append(out, RuleCandidate{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func relativeFindingPath(dataset, path string) string {
	dataset = filepath.Clean(strings.TrimSpace(dataset))
	path = filepath.Clean(strings.TrimSpace(path))
	if dataset == "" || path == "" {
		return normalizeEvalPath(path)
	}
	rel, err := filepath.Rel(dataset, path)
	if err != nil {
		return normalizeEvalPath(path)
	}
	return normalizeEvalPath(rel)
}

func normalizeEvalPath(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." {
		return ""
	}
	return filepath.ToSlash(path)
}

func findingKey(path, category string) string {
	return normalizeEvalPath(path) + "::" + strings.ToLower(strings.TrimSpace(category))
}

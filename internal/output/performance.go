package output

import (
	"sort"
	"strings"

	"snablr/internal/diff"
	"snablr/internal/scanner"
)

type BaselinePerformanceAware interface {
	SetBaselinePerformance(*diff.PerformanceSummary)
}

func SetBaselinePerformance(sink scanner.FindingSink, summary *diff.PerformanceSummary) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(BaselinePerformanceAware); ok {
		aware.SetBaselinePerformance(summary)
	}
}

func buildPerformanceSummary(summary summarySnapshot, findings []scanner.Finding) diff.PerformanceSummary {
	duration := summary.EndedAt.Sub(summary.StartedAt)
	if summary.StartedAt.IsZero() || summary.EndedAt.IsZero() || duration < 0 {
		duration = 0
	}

	filesPerSecond := 0.0
	if duration > 0 && summary.FilesScanned > 0 {
		filesPerSecond = float64(summary.FilesScanned) / duration.Seconds()
	}

	return diff.PerformanceSummary{
		FilesScanned:               summary.FilesScanned,
		FindingsTotal:              summary.MatchesFound,
		DurationMS:                 duration.Milliseconds(),
		FilesPerSecond:             filesPerSecond,
		ClassificationDistribution: buildClassificationDistribution(findings),
	}
}

func buildPerformanceComparison(current diff.PerformanceSummary, baseline *diff.PerformanceSummary) *diff.PerformanceComparison {
	if baseline == nil {
		return nil
	}

	return &diff.PerformanceComparison{
		FindingsDelta:         current.FindingsTotal - baseline.FindingsTotal,
		DurationDeltaMS:       current.DurationMS - baseline.DurationMS,
		FilesPerSecondDelta:   current.FilesPerSecond - baseline.FilesPerSecond,
		ClassificationChanges: buildClassificationDeltas(current.ClassificationDistribution, baseline.ClassificationDistribution),
	}
}

func buildClassificationDistribution(findings []scanner.Finding) []diff.ClassificationSummary {
	if len(findings) == 0 {
		return nil
	}

	counts := make(map[string]int)
	for _, finding := range findings {
		class := strings.ToLower(strings.TrimSpace(finding.TriageClass))
		if class == "" {
			class = "unclassified"
		}
		counts[class]++
	}

	out := make([]diff.ClassificationSummary, 0, len(counts))
	for class, count := range counts {
		out = append(out, diff.ClassificationSummary{Class: class, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Class < out[j].Class
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func buildClassificationDeltas(current, baseline []diff.ClassificationSummary) []diff.ClassificationDelta {
	counts := make(map[string]diff.ClassificationDelta)
	for _, item := range baseline {
		counts[item.Class] = diff.ClassificationDelta{Class: item.Class, Prev: item.Count}
	}
	for _, item := range current {
		delta := counts[item.Class]
		delta.Class = item.Class
		delta.Curr = item.Count
		counts[item.Class] = delta
	}

	out := make([]diff.ClassificationDelta, 0, len(counts))
	for _, item := range counts {
		item.Delta = item.Curr - item.Prev
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := absInt(out[i].Delta)
		right := absInt(out[j].Delta)
		if left == right {
			return out[i].Class < out[j].Class
		}
		return left > right
	})
	return out
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

package app

import (
	"context"
	"fmt"
	"strings"

	"snablr/internal/benchmark"
	"snablr/internal/eval"
)

func RunBenchmark(ctx context.Context, opts BenchmarkOptions) error {
	cfg, err := benchmark.LoadConfig(opts.ConfigPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.Dataset) != "" {
		cfg.Dataset = opts.Dataset
	}
	if strings.TrimSpace(opts.RulesDirectory) != "" {
		cfg.RulesDirectory = opts.RulesDirectory
	}
	if strings.TrimSpace(opts.LogLevel) != "" {
		cfg.LogLevel = opts.LogLevel
	}

	report, err := benchmark.Run(ctx, cfg)
	if err != nil {
		return err
	}

	fmt.Println("Snablr Benchmark Summary")
	fmt.Printf("Dataset: %s\n", report.Dataset)
	fmt.Printf("Duration: %dms\n", report.DurationMS)
	if report.TimeToFirstFindingSet {
		fmt.Printf("Time to first finding: %dms\n", report.TimeToFirstFindingMS)
	} else {
		fmt.Println("Time to first finding: none")
	}
	fmt.Printf("Files visited: %d\n", report.Metrics.Counters.FilesVisited)
	fmt.Printf("Files read: %d\n", report.Metrics.Counters.FilesRead)
	fmt.Printf("Matches found: %d\n", report.Metrics.Counters.MatchesFound)
	fmt.Printf("Grouped findings: %d\n", report.GroupedFindings)
	fmt.Printf("High-confidence findings: %d\n", report.HighConfidenceFindings)

	if strings.TrimSpace(opts.OutPath) != "" {
		if err := benchmark.WriteJSON(report, opts.OutPath); err != nil {
			return err
		}
		fmt.Printf("Wrote benchmark report: %s\n", opts.OutPath)
	}
	return nil
}

func RunEval(ctx context.Context, opts EvalOptions) error {
	if strings.TrimSpace(opts.Dataset) == "" {
		return fmt.Errorf("dataset is required: pass --dataset <dir>")
	}
	if strings.TrimSpace(opts.LabelsPath) == "" {
		return fmt.Errorf("labels file is required: pass --labels <file>")
	}

	report, err := eval.Run(ctx, benchmark.Config{
		Dataset:        opts.Dataset,
		SnablrConfig:   opts.ConfigPath,
		RulesDirectory: opts.RulesDirectory,
		LogLevel:       opts.LogLevel,
	}, opts.LabelsPath)
	if err != nil {
		return err
	}

	fmt.Println("Snablr Evaluation Summary")
	fmt.Printf("Dataset: %s\n", report.Dataset)
	fmt.Printf("Expected findings: %d\n", report.Summary.ExpectedTotal)
	fmt.Printf("Matched findings: %d\n", report.Summary.MatchedTotal)
	fmt.Printf("Missed findings: %d\n", report.Summary.MissedTotal)
	fmt.Printf("Noisy findings: %d\n", report.Summary.NoisyTotal)
	fmt.Printf("Duplicate findings: %d\n", report.Summary.DuplicateTotal)
	fmt.Printf("Precision-like: %.2f\n", report.Summary.PrecisionLike)
	fmt.Printf("Recall-like: %.2f\n", report.Summary.RecallLike)
	if len(report.NoisyRuleCandidates) > 0 {
		fmt.Println("Top noisy rule candidates:")
		limit := len(report.NoisyRuleCandidates)
		if limit > 5 {
			limit = 5
		}
		for _, candidate := range report.NoisyRuleCandidates[:limit] {
			fmt.Printf("- %s (%d)\n", candidate.Name, candidate.Count)
		}
	}
	if len(report.MissedRuleCandidates) > 0 {
		fmt.Println("Top missed rule candidates:")
		limit := len(report.MissedRuleCandidates)
		if limit > 5 {
			limit = 5
		}
		for _, candidate := range report.MissedRuleCandidates[:limit] {
			fmt.Printf("- %s (%d)\n", candidate.Name, candidate.Count)
		}
	}

	if strings.TrimSpace(opts.OutPath) != "" {
		if err := eval.WriteJSON(report, opts.OutPath); err != nil {
			return err
		}
		fmt.Printf("Wrote evaluation report: %s\n", opts.OutPath)
	}
	return nil
}

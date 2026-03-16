package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

func LoadConfig(path string) (Config, error) {
	cfg := Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read benchmark config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse benchmark config %s: %w", path, err)
	}
	return cfg, nil
}

func Run(ctx context.Context, cfg Config) (Report, error) {
	resolved, rulesPaths, manager, logger, err := resolve(cfg)
	if err != nil {
		return Report{}, err
	}

	startedAt := time.Now().UTC()
	recorder := metrics.NewCollector()
	timer := recorder.StartPhase("dataset_scan")
	sink := newCaptureSink(startedAt)

	engine := scanner.NewEngine(scanner.Options{
		Workers:          resolved.WorkerCount,
		MaxFileSizeBytes: resolved.MaxFileSize,
		MaxReadBytes:     resolved.MaxReadBytes,
		SnippetBytes:     resolved.SnippetBytes,
		Recorder:         recorder,
	}, manager, sink, logger)

	err = engine.Run(ctx, []string{resolved.Dataset})
	timer.Stop()

	endedAt := time.Now().UTC()
	report := buildReport(resolved, rulesPaths, startedAt, endedAt, recorder.Snapshot(), sink.findingsSnapshot(), sink.timeToFirstFinding())
	if err != nil {
		return report, err
	}
	return report, nil
}

func WriteJSON(report Report, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("benchmark output path cannot be empty")
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

func buildReport(cfg Config, rulesPaths []string, startedAt, endedAt time.Time, snapshot metrics.Snapshot, findings []scanner.Finding, firstFinding time.Duration) Report {
	report := Report{
		Name:             strings.TrimSpace(cfg.Name),
		Dataset:          cfg.Dataset,
		RulesDirectories: append([]string{}, rulesPaths...),
		StartedAt:        startedAt,
		EndedAt:          endedAt,
		DurationMS:       endedAt.Sub(startedAt).Milliseconds(),
		Metrics:          snapshot,
		GroupedFindings:  len(findings),
		Findings:         findings,
	}
	if firstFinding > 0 {
		report.TimeToFirstFindingMS = firstFinding.Milliseconds()
		report.TimeToFirstFindingSet = true
	}

	byCategory := make(map[string]int)
	bySeverity := make(map[string]int)
	byRule := make(map[string]int)
	for _, finding := range findings {
		if strings.EqualFold(finding.Confidence, "high") {
			report.HighConfidenceFindings++
		}
		if category := strings.TrimSpace(finding.Category); category != "" {
			byCategory[category]++
		}
		if severity := strings.TrimSpace(finding.Severity); severity != "" {
			bySeverity[severity]++
		}
		if ruleID := strings.TrimSpace(finding.RuleID); ruleID != "" {
			byRule[ruleID]++
		}
	}
	report.FindingsByCategory = toCountStats(byCategory)
	report.FindingsBySeverity = toCountStats(bySeverity)
	report.FindingsByRule = toCountStats(byRule)
	return report
}

func resolve(cfg Config) (Config, []string, *rules.Manager, *logx.Logger, error) {
	out := cfg
	if strings.TrimSpace(out.SnablrConfig) != "" {
		baseCfg, err := config.Load(out.SnablrConfig)
		if err != nil {
			return Config{}, nil, nil, nil, fmt.Errorf("load snablr config: %w", err)
		}
		if out.WorkerCount <= 0 {
			out.WorkerCount = baseCfg.Scan.WorkerCount
		}
		if out.MaxFileSize <= 0 {
			out.MaxFileSize = baseCfg.Scan.MaxFileSize
		}
		if strings.TrimSpace(out.LogLevel) == "" {
			out.LogLevel = baseCfg.App.LogLevel
		}
		if strings.TrimSpace(out.RulesDirectory) == "" {
			out.RulesDirectory = baseCfg.Rules.Directory
		}
	}

	if out.SnippetBytes <= 0 {
		out.SnippetBytes = 120
	}
	if out.MaxReadBytes <= 0 {
		out.MaxReadBytes = out.MaxFileSize
	}
	if out.MaxFileSize <= 0 {
		out.MaxFileSize = 10 * 1024 * 1024
	}
	if strings.TrimSpace(out.LogLevel) == "" {
		out.LogLevel = "info"
	}
	out.Dataset = filepath.Clean(strings.TrimSpace(out.Dataset))
	if out.Dataset == "" {
		return Config{}, nil, nil, nil, fmt.Errorf("benchmark dataset is required")
	}

	info, err := os.Stat(out.Dataset)
	if err != nil {
		return Config{}, nil, nil, nil, fmt.Errorf("stat dataset %s: %w", out.Dataset, err)
	}
	if !info.IsDir() {
		return Config{}, nil, nil, nil, fmt.Errorf("benchmark dataset %s is not a directory", out.Dataset)
	}

	rulesPaths := config.Default().RulePaths()
	if strings.TrimSpace(out.RulesDirectory) != "" {
		rulesPaths = []string{out.RulesDirectory}
	}
	manager, issues, err := rules.LoadManager(rulesPaths, false, rules.ManagerOptions{})
	if err != nil {
		return Config{}, nil, nil, nil, fmt.Errorf("load rules: %w", err)
	}
	logger := logx.New(out.LogLevel)
	for _, issue := range issues {
		logger.Warnf("rule warning: %v", issue)
	}
	return out, rulesPaths, manager, logger, nil
}

func toCountStats(values map[string]int) []CountStat {
	if len(values) == 0 {
		return nil
	}
	out := make([]CountStat, 0, len(values))
	for name, count := range values {
		out = append(out, CountStat{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	return out
}

type captureSink struct {
	mu           sync.Mutex
	startedAt    time.Time
	firstFinding time.Time
	findings     []scanner.Finding
}

func newCaptureSink(startedAt time.Time) *captureSink {
	return &captureSink{startedAt: startedAt}
}

func (c *captureSink) WriteFinding(f scanner.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstFinding.IsZero() {
		c.firstFinding = time.Now().UTC()
	}
	c.findings = append(c.findings, f)
	return nil
}

func (c *captureSink) Close() error { return nil }

func (c *captureSink) findingsSnapshot() []scanner.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]scanner.Finding, len(c.findings))
	copy(out, c.findings)
	return out
}

func (c *captureSink) timeToFirstFinding() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.firstFinding.IsZero() {
		return 0
	}
	return c.firstFinding.Sub(c.startedAt)
}

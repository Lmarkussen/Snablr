package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/output"
	"snablr/internal/planner"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/state"
	"snablr/internal/ui"
	"snablr/pkg/logx"
)

type ScanOptions struct {
	ConfigPath                 string
	Targets                    []string
	TargetsFile                string
	Username                   string
	Password                   string
	Share                      []string
	ExcludeShare               []string
	Path                       []string
	ExcludePath                []string
	MaxDepth                   int
	Domain                     string
	RulesDirectory             string
	WorkerCount                int
	MaxFileSize                int64
	NoLDAP                     bool
	DomainController           string
	BaseDN                     string
	DiscoverDFS                bool
	PrioritizeADShares         bool
	OnlyADShares               bool
	Baseline                   string
	MaxScanTime                string
	CheckpointFile             string
	Resume                     bool
	SkipReachabilityCheck      bool
	ReachabilityTimeoutSeconds int
	OutputFormat               string
	JSONOut                    string
	HTMLOut                    string
	CSVOut                     string
	MDOut                      string
	LogLevel                   string
}

type RulesOptions struct {
	ConfigPath     string
	RulesDirectory string
	LogLevel       string
}

type RulesShowOptions struct {
	RulesOptions
	ID string
}

type RulesTestOptions struct {
	RulesOptions
	RuleFile  string
	InputFile string
	Verbose   bool
}

type RulesTestDirOptions struct {
	RulesOptions
	FixturesDir string
	Verbose     bool
}

type DiffOptions struct {
	OldPath string
	NewPath string
}

type DiscoverOptions struct {
	ConfigPath                 string
	Targets                    []string
	TargetsFile                string
	Username                   string
	Password                   string
	Domain                     string
	NoLDAP                     bool
	DomainController           string
	BaseDN                     string
	DiscoverDFS                bool
	SkipReachabilityCheck      bool
	ReachabilityTimeoutSeconds int
	LogLevel                   string
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func RunScan(ctx context.Context, opts ScanOptions) (err error) {
	cfg, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	applyScanOverrides(&cfg, opts)
	if err := validateScanConfig(cfg); err != nil {
		return err
	}
	cfg.Scan.WorkerCount = scanner.ResolveWorkerCount(cfg.Scan.WorkerCount)
	logger.Infof("using %d file scan worker(s)", cfg.Scan.WorkerCount)

	scanCtx := ctx
	var cancel context.CancelFunc
	maxScanDuration, err := cfg.Scan.MaxScanDuration()
	if err != nil {
		return err
	}
	if maxScanDuration > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, maxScanDuration)
		defer cancel()
	}

	manager, err := loadRuleManager(cfg, logger)
	if err != nil {
		return err
	}
	if issues := manager.Validate(); len(issues) > 0 {
		for _, issue := range issues {
			logger.Warnf("%s", issue.Error())
		}
		return fmt.Errorf("rule validation failed with %d issue(s)", len(issues))
	}

	sink, err := output.NewWriter(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	defer func() {
		if sink == nil {
			return
		}
		if closeErr := sink.Close(); closeErr != nil {
			if logger != nil {
				logger.Errorf("output finalization failed: %v", closeErr)
			}
			if err == nil {
				err = closeErr
			}
		}
	}()

	if strings.TrimSpace(cfg.Scan.Baseline) != "" {
		baseline, err := diff.LoadJSON(cfg.Scan.Baseline)
		if err != nil {
			return fmt.Errorf("load baseline %s: %w", cfg.Scan.Baseline, err)
		}
		output.SetBaselineFindings(sink, baseline.Findings)
		logger.Infof("loaded %d baseline finding(s) for diff reporting", len(baseline.Findings))
	}

	recorder := metrics.NewCollector()
	totalTimer := recorder.StartPhase("total_scan")
	defer func() {
		totalTimer.Stop()
		output.SetMetricsSnapshot(sink, recorder.Snapshot())
	}()

	checkpoints, err := state.NewManager(cfg.Scan.CheckpointFile, cfg.Scan.Resume, 10*time.Second)
	if err != nil {
		return fmt.Errorf("open checkpoint state: %w", err)
	}
	if checkpoints != nil {
		checkpoints.Start(scanCtx)
		defer checkpoints.Close()
	}

	engine := scanner.NewEngine(scanner.Options{
		Workers:          cfg.Scan.WorkerCount,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     cfg.Scan.MaxFileSize,
		SnippetBytes:     120,
		Recorder:         recorder,
	}, manager, sink, logger)

	resolvedTargets, err := discovery.Resolve(scanCtx, cfg.Scan, logger, recorder)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Warnf("max scan time reached during target discovery")
			return nil
		}
		return err
	}
	if len(resolvedTargets.DiscoveredHosts) > 0 {
		logger.Infof("ldap discovery returned %d host(s)", len(resolvedTargets.DiscoveredHosts))
	}
	if len(resolvedTargets.DFSTargets) > 0 {
		logger.Infof("dfs discovery returned %d target(s)", len(resolvedTargets.DFSTargets))
	}
	logger.Infof("Targets loaded: %d", resolvedTargets.Stats.Loaded)
	logger.Infof("Unique targets: %d", resolvedTargets.Stats.Unique)
	logger.Infof("Reachable SMB hosts: %d", resolvedTargets.Stats.Reachable)
	logger.Infof("Skipped hosts: %d", resolvedTargets.Stats.Skipped)

	hostInputs := make([]planner.HostInput, 0, len(resolvedTargets.ReachableTargets))
	for _, target := range resolvedTargets.ReachableTargets {
		if strings.TrimSpace(target.Hostname) != "" {
			hostInputs = append(hostInputs, planner.HostInput{
				Host:   target.Hostname,
				Source: target.Source,
			})
			continue
		}
		if strings.TrimSpace(target.IP) != "" {
			hostInputs = append(hostInputs, planner.HostInput{
				Host:   target.IP,
				Source: target.Source,
			})
		}
	}
	if len(hostInputs) == 0 {
		return fmt.Errorf("no reachable SMB targets available after discovery and reachability checks; provide --targets, adjust discovery settings, or use --skip-reachability-check to inspect unreachable targets")
	}

	planningTimer := recorder.StartPhase("host_planning")
	plannedHosts := planner.PlanHosts(hostInputs)
	planningTimer.Stop()
	if len(plannedHosts) > 0 {
		logger.Infof("scan plan prepared for %d host(s); highest priority=%d (%s)", len(plannedHosts), plannedHosts[0].Priority, plannedHosts[0].Reason)
	}

	var progress *ui.ProgressReporter
	if ui.ShouldShowProgress(cfg.Output.Format) {
		progress = ui.NewProgressReporter(os.Stderr, recorder, 3*time.Second)
		progress.SetTargetTotal(len(plannedHosts))
		progress.Start(scanCtx)
		defer progress.Close()
	}

	var errs []error
	timedOut := false
	scanTimer := recorder.StartPhase("host_scanning")
	for _, target := range plannedHosts {
		if err := scanCtx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				break
			}
			return err
		}
		if checkpoints != nil && checkpoints.ShouldSkipHost(target.Host) {
			logger.Infof("resume: skipping completed host %s", target.Host)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		if progress != nil {
			progress.SetCurrentHost(target.Host)
		}
		if err := scanHost(scanCtx, target.Host, target.Source, resolvedTargets.DFSTargets, checkpoints, recorder, cfg, engine, sink, logger); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				if progress != nil {
					progress.SetStatus("time limit reached")
					progress.MarkTargetProcessed()
				}
				break
			}
			errs = append(errs, err)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		if checkpoints != nil {
			checkpoints.MarkHostComplete(target.Host)
		}
		if progress != nil {
			progress.MarkTargetProcessed()
		}
	}
	scanTimer.Stop()
	if timedOut {
		if progress != nil {
			progress.SetStatus("time limit reached")
		}
		logger.Warnf("max scan time reached; stopping scan gracefully")
		return nil
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func RunRulesList(opts RulesOptions) error {
	_, _, manager, err := loadRuntime(opts.ConfigPath, opts.LogLevel, opts.RulesDirectory)
	if err != nil {
		return err
	}

	ruleset := manager.EnabledRules()
	sort.Slice(ruleset, func(i, j int) bool { return ruleset[i].ID < ruleset[j].ID })

	fmt.Printf("%-32s %-12s %-10s %-12s %s\n", "ID", "TYPE", "SEVERITY", "ACTION", "NAME")
	for _, rule := range ruleset {
		fmt.Printf("%-32s %-12s %-10s %-12s %s\n", rule.ID, rule.Type, rule.Severity, rule.Action, rule.Name)
	}
	return nil
}

func RunDiff(opts DiffOptions) error {
	if strings.TrimSpace(opts.OldPath) == "" {
		return fmt.Errorf("missing required flag --old: provide the baseline JSON report path")
	}
	if strings.TrimSpace(opts.NewPath) == "" {
		return fmt.Errorf("missing required flag --new: provide the current JSON report path")
	}

	previous, err := diff.LoadJSON(opts.OldPath)
	if err != nil {
		return err
	}
	current, err := diff.LoadJSON(opts.NewPath)
	if err != nil {
		return err
	}

	result := diff.Compare(previous.Findings, current.Findings)
	summary := result.Summary()

	fmt.Println("Snablr Diff Summary")
	fmt.Printf("New: %d\n", summary.New)
	fmt.Printf("Removed: %d\n", summary.Removed)
	fmt.Printf("Changed: %d\n", summary.Changed)
	fmt.Printf("Unchanged: %d\n", summary.Unchanged)

	printDiffSection := func(title string, findings []scanner.Finding) {
		if len(findings) == 0 {
			return
		}
		fmt.Printf("\n%s:\n", title)
		limit := len(findings)
		if limit > 10 {
			limit = 10
		}
		for _, finding := range findings[:limit] {
			fmt.Printf("- [%s] %s %s %s\n", strings.ToUpper(finding.Severity), finding.RuleID, outputPathForDiff(finding), strings.TrimSpace(finding.Match))
		}
		if len(findings) > limit {
			fmt.Printf("  ... %d more\n", len(findings)-limit)
		}
	}

	printDiffSection("New Findings", result.New)
	printDiffSection("Removed Findings", result.Removed)
	if len(result.Changed) > 0 {
		fmt.Println("\nChanged Findings:")
		limit := len(result.Changed)
		if limit > 10 {
			limit = 10
		}
		for _, changed := range result.Changed[:limit] {
			fmt.Printf("- [%s] %s %s fields=%s\n",
				strings.ToUpper(changed.Current.Severity),
				changed.Current.RuleID,
				outputPathForDiff(changed.Current),
				strings.Join(changed.ChangedFields, ","),
			)
		}
		if len(result.Changed) > limit {
			fmt.Printf("  ... %d more\n", len(result.Changed)-limit)
		}
	}

	return nil
}

func RunDiscover(ctx context.Context, opts DiscoverOptions) error {
	cfg, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	applyDiscoverOverrides(&cfg, opts)
	if err := validateDiscoverConfig(cfg.Scan); err != nil {
		return err
	}

	result, err := discovery.Resolve(ctx, cfg.Scan, logger, nil)
	if err != nil {
		return err
	}

	fmt.Println("Snablr Discovery Summary")
	fmt.Printf("Targets loaded: %d\n", result.Stats.Loaded)
	fmt.Printf("Unique targets: %d\n", result.Stats.Unique)
	fmt.Printf("Reachable SMB hosts: %d\n", result.Stats.Reachable)
	fmt.Printf("Skipped hosts: %d\n", result.Stats.Skipped)

	if len(result.DiscoveredHosts) > 0 {
		fmt.Printf("\nLDAP hosts (%d):\n", len(result.DiscoveredHosts))
		limit := len(result.DiscoveredHosts)
		if limit > 20 {
			limit = 20
		}
		for _, host := range result.DiscoveredHosts[:limit] {
			name := strings.TrimSpace(host.DNSHostname)
			if name == "" {
				name = strings.TrimSpace(host.Hostname)
			}
			fmt.Printf("- %s", valueOrUnknown(name))
			if strings.TrimSpace(host.OperatingSystem) != "" {
				fmt.Printf("  os=%s", host.OperatingSystem)
			}
			if strings.TrimSpace(host.IP) != "" {
				fmt.Printf("  ip=%s", host.IP)
			}
			fmt.Println()
		}
		if len(result.DiscoveredHosts) > limit {
			fmt.Printf("  ... %d more\n", len(result.DiscoveredHosts)-limit)
		}
	}

	if len(result.DFSTargets) > 0 {
		fmt.Printf("\nDFS targets (%d):\n", len(result.DFSTargets))
		limit := len(result.DFSTargets)
		if limit > 20 {
			limit = 20
		}
		for _, target := range result.DFSTargets[:limit] {
			fmt.Printf("- namespace=%s target=%s/%s link=%s\n",
				valueOrUnknown(target.NamespacePath),
				valueOrUnknown(target.TargetServer),
				valueOrUnknown(target.TargetShare),
				valueOrUnknown(target.LinkPath),
			)
		}
		if len(result.DFSTargets) > limit {
			fmt.Printf("  ... %d more\n", len(result.DFSTargets)-limit)
		}
	}

	if len(result.ReachableTargets) > 0 {
		fmt.Printf("\nReachable targets (%d):\n", len(result.ReachableTargets))
		limit := len(result.ReachableTargets)
		if limit > 30 {
			limit = 30
		}
		for _, target := range result.ReachableTargets[:limit] {
			name := strings.TrimSpace(target.Hostname)
			if name == "" {
				name = strings.TrimSpace(target.IP)
			}
			fmt.Printf("- %s  source=%s\n", valueOrUnknown(name), valueOrUnknown(target.Source))
		}
		if len(result.ReachableTargets) > limit {
			fmt.Printf("  ... %d more\n", len(result.ReachableTargets)-limit)
		}
	}

	return nil
}

func RunRulesValidate(opts RulesOptions) error {
	cfg, logger, manager, err := loadRuntime(opts.ConfigPath, opts.LogLevel, opts.RulesDirectory)
	if err != nil {
		return err
	}

	issues := manager.Validate()
	if len(issues) == 0 {
		fmt.Printf("validated %d rule files, no issues found\n", len(manager.RuleFiles()))
		return nil
	}

	for _, issue := range issues {
		logger.Warnf("%s", issue.Error())
	}
	if cfg.Rules.FailOnInvalid {
		return fmt.Errorf("rule validation failed with %d issue(s)", len(issues))
	}
	return fmt.Errorf("rule validation reported %d issue(s)", len(issues))
}

func RunRulesShow(opts RulesShowOptions) error {
	if strings.TrimSpace(opts.ID) == "" {
		return fmt.Errorf("rule id is required")
	}

	_, _, manager, err := loadRuntime(opts.ConfigPath, opts.LogLevel, opts.RulesDirectory)
	if err != nil {
		return err
	}

	for _, rule := range manager.Rules() {
		if rule.ID != opts.ID {
			continue
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rule)
	}
	return fmt.Errorf("rule %q not found", opts.ID)
}

func RunRulesTest(opts RulesTestOptions) error {
	if strings.TrimSpace(opts.RuleFile) == "" {
		return fmt.Errorf("rule file is required")
	}
	if strings.TrimSpace(opts.InputFile) == "" {
		return fmt.Errorf("input file is required")
	}

	cfg, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	summary, issues, err := rules.TestRuleFile(opts.RuleFile, opts.InputFile)
	if err != nil {
		return err
	}
	if len(issues) > 0 {
		for _, issue := range issues {
			logger.Warnf("%s", issue.Error())
		}
		return &ExitError{
			Code: 1,
			Err:  fmt.Errorf("rule validation failed with %d issue(s)", len(issues)),
		}
	}

	printRuleTestSummary(summary, opts.Verbose)
	if len(summary.Matches) > 0 {
		return &ExitError{
			Code: 2,
			Err:  fmt.Errorf("rule matched"),
		}
	}
	_ = cfg
	return nil
}

func RunRulesTestDir(opts RulesTestDirOptions) error {
	rulesDir := strings.TrimSpace(opts.RulesDirectory)
	if rulesDir == "" {
		cfg, _, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
		if err != nil {
			return err
		}
		rulesDir = cfg.RulePaths()[0]
	}
	if strings.TrimSpace(opts.FixturesDir) == "" {
		return fmt.Errorf("fixtures directory is required")
	}

	_, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	summary, issues, err := rules.TestRuleDirectory(rulesDir, opts.FixturesDir)
	if err != nil {
		return err
	}
	if len(issues) > 0 {
		for _, issue := range issues {
			logger.Warnf("%s", issue.Error())
		}
		return &ExitError{
			Code: 1,
			Err:  fmt.Errorf("rule validation failed with %d issue(s)", len(issues)),
		}
	}

	printRuleTestSummary(summary, opts.Verbose)
	if len(summary.Matches) > 0 {
		return &ExitError{
			Code: 2,
			Err:  fmt.Errorf("rule matched"),
		}
	}
	return nil
}

func loadRuntime(configPath, logLevelOverride, rulesDirOverride string) (config.Config, *logx.Logger, *rules.Manager, error) {
	cfg, logger, err := loadConfigAndLogger(configPath, logLevelOverride)
	if err != nil {
		return config.Config{}, nil, nil, fmt.Errorf("load config: %w", err)
	}
	if strings.TrimSpace(rulesDirOverride) != "" {
		cfg.Rules.Directory = rulesDirOverride
	}

	manager, err := loadRuleManager(cfg, logger)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	return cfg, logger, manager, nil
}

func loadRuleManager(cfg config.Config, logger *logx.Logger) (*rules.Manager, error) {
	manager, ruleErrs, err := rules.LoadManager(cfg.RulePaths(), cfg.Rules.FailOnInvalid, rules.ManagerOptions{})
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	for _, ruleErr := range ruleErrs {
		logger.Warnf("rule warning: %v", ruleErr)
	}
	return manager, nil
}

func loadConfigAndLogger(configPath, logLevelOverride string) (config.Config, *logx.Logger, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	if strings.TrimSpace(logLevelOverride) != "" {
		cfg.App.LogLevel = logLevelOverride
	}
	return cfg, logx.New(cfg.App.LogLevel), nil
}

func applyScanOverrides(cfg *config.Config, opts ScanOptions) {
	if len(opts.Targets) > 0 {
		cfg.Scan.Targets = append([]string{}, opts.Targets...)
	}
	if strings.TrimSpace(opts.TargetsFile) != "" {
		cfg.Scan.TargetsFile = opts.TargetsFile
	}
	if strings.TrimSpace(opts.Username) != "" {
		cfg.Scan.Username = opts.Username
	}
	if opts.Password != "" {
		cfg.Scan.Password = opts.Password
	}
	if len(opts.Share) > 0 {
		cfg.Scan.Share = append([]string{}, opts.Share...)
	}
	if len(opts.ExcludeShare) > 0 {
		cfg.Scan.ExcludeShare = append([]string{}, opts.ExcludeShare...)
	}
	if len(opts.Path) > 0 {
		cfg.Scan.Path = append([]string{}, opts.Path...)
	}
	if len(opts.ExcludePath) > 0 {
		cfg.Scan.ExcludePath = append([]string{}, opts.ExcludePath...)
	}
	if opts.MaxDepth > 0 {
		cfg.Scan.MaxDepth = opts.MaxDepth
	}
	if strings.TrimSpace(opts.RulesDirectory) != "" {
		cfg.Rules.Directory = opts.RulesDirectory
	}
	if opts.WorkerCount > 0 {
		cfg.Scan.WorkerCount = opts.WorkerCount
	}
	if opts.MaxFileSize > 0 {
		cfg.Scan.MaxFileSize = opts.MaxFileSize
	}
	if strings.TrimSpace(opts.Domain) != "" {
		cfg.Scan.Domain = opts.Domain
	}
	if opts.NoLDAP {
		cfg.Scan.NoLDAP = true
	}
	if strings.TrimSpace(opts.DomainController) != "" {
		cfg.Scan.DomainController = opts.DomainController
	}
	if strings.TrimSpace(opts.BaseDN) != "" {
		cfg.Scan.BaseDN = opts.BaseDN
	}
	if opts.DiscoverDFS {
		cfg.Scan.DiscoverDFS = true
	}
	if opts.PrioritizeADShares {
		cfg.Scan.PrioritizeADShares = true
	}
	if opts.OnlyADShares {
		cfg.Scan.OnlyADShares = true
	}
	if strings.TrimSpace(opts.Baseline) != "" {
		cfg.Scan.Baseline = opts.Baseline
	}
	if strings.TrimSpace(opts.MaxScanTime) != "" {
		cfg.Scan.MaxScanTime = opts.MaxScanTime
	}
	if strings.TrimSpace(opts.CheckpointFile) != "" {
		cfg.Scan.CheckpointFile = opts.CheckpointFile
	}
	if opts.Resume {
		cfg.Scan.Resume = true
	}
	if opts.SkipReachabilityCheck {
		cfg.Scan.SkipReachabilityCheck = true
	}
	if opts.ReachabilityTimeoutSeconds > 0 {
		cfg.Scan.ReachabilityTimeoutSeconds = opts.ReachabilityTimeoutSeconds
	}
	if strings.TrimSpace(opts.OutputFormat) != "" {
		cfg.Output.Format = opts.OutputFormat
	}
	if strings.TrimSpace(opts.JSONOut) != "" {
		cfg.Output.JSONOut = opts.JSONOut
	}
	if strings.TrimSpace(opts.HTMLOut) != "" {
		cfg.Output.HTMLOut = opts.HTMLOut
	}
	if strings.TrimSpace(opts.CSVOut) != "" {
		cfg.Output.CSVOut = opts.CSVOut
	}
	if strings.TrimSpace(opts.MDOut) != "" {
		cfg.Output.MDOut = opts.MDOut
	}
	if strings.TrimSpace(opts.LogLevel) != "" {
		cfg.App.LogLevel = opts.LogLevel
	}
}

func applyDiscoverOverrides(cfg *config.Config, opts DiscoverOptions) {
	if len(opts.Targets) > 0 {
		cfg.Scan.Targets = append([]string{}, opts.Targets...)
	}
	if strings.TrimSpace(opts.TargetsFile) != "" {
		cfg.Scan.TargetsFile = opts.TargetsFile
	}
	if strings.TrimSpace(opts.Username) != "" {
		cfg.Scan.Username = opts.Username
	}
	if opts.Password != "" {
		cfg.Scan.Password = opts.Password
	}
	if strings.TrimSpace(opts.Domain) != "" {
		cfg.Scan.Domain = opts.Domain
	}
	if opts.NoLDAP {
		cfg.Scan.NoLDAP = true
	}
	if strings.TrimSpace(opts.DomainController) != "" {
		cfg.Scan.DomainController = opts.DomainController
	}
	if strings.TrimSpace(opts.BaseDN) != "" {
		cfg.Scan.BaseDN = opts.BaseDN
	}
	if opts.DiscoverDFS {
		cfg.Scan.DiscoverDFS = true
	}
	if opts.SkipReachabilityCheck {
		cfg.Scan.SkipReachabilityCheck = true
	}
	if opts.ReachabilityTimeoutSeconds > 0 {
		cfg.Scan.ReachabilityTimeoutSeconds = opts.ReachabilityTimeoutSeconds
	}
	if strings.TrimSpace(opts.LogLevel) != "" {
		cfg.App.LogLevel = opts.LogLevel
	}
}

func validateScanConfig(cfg config.Config) error {
	if strings.TrimSpace(cfg.Scan.Username) == "" {
		return fmt.Errorf("missing SMB username: set scan.username in config or pass --username")
	}
	if cfg.Scan.Password == "" {
		return fmt.Errorf("missing SMB password: set scan.password in config or pass --password")
	}
	if _, err := cfg.Scan.MaxScanDuration(); err != nil {
		return err
	}
	if cfg.Scan.MaxDepth < 0 {
		return fmt.Errorf("max_depth cannot be negative")
	}
	if cfg.Scan.Resume && strings.TrimSpace(cfg.Scan.CheckpointFile) == "" {
		return fmt.Errorf("resume requires a checkpoint file: set scan.checkpoint_file or pass --checkpoint-file")
	}
	switch strings.ToLower(cfg.Output.Format) {
	case "console", "json", "html", "all":
	default:
		return fmt.Errorf("unsupported output format %q: use console, json, html, or all", cfg.Output.Format)
	}
	if (strings.EqualFold(cfg.Output.Format, "json") || strings.EqualFold(cfg.Output.Format, "all")) && strings.TrimSpace(cfg.Output.JSONOut) == "" {
		return fmt.Errorf("output format %q requires json_out: set output.json_out or pass --json-out", cfg.Output.Format)
	}
	if (strings.EqualFold(cfg.Output.Format, "html") || strings.EqualFold(cfg.Output.Format, "all")) && strings.TrimSpace(cfg.Output.HTMLOut) == "" {
		return fmt.Errorf("output format %q requires html_out: set output.html_out or pass --html-out", cfg.Output.Format)
	}
	return nil
}

func validateDiscoverConfig(scanCfg config.ScanConfig) error {
	if len(scanCfg.Targets) == 0 && strings.TrimSpace(scanCfg.TargetsFile) == "" && scanCfg.NoLDAP {
		return fmt.Errorf("no targets available: provide --targets/--targets-file or allow LDAP discovery by removing --no-ldap")
	}
	needsLDAPCreds := (!scanCfg.NoLDAP && len(scanCfg.Targets) == 0 && strings.TrimSpace(scanCfg.TargetsFile) == "") || scanCfg.DiscoverDFS
	if needsLDAPCreds && strings.TrimSpace(scanCfg.Username) == "" {
		return fmt.Errorf("ldap discovery needs credentials: set scan.username in config or pass --username")
	}
	if needsLDAPCreds && scanCfg.Password == "" {
		return fmt.Errorf("ldap discovery needs credentials: set scan.password in config or pass --password")
	}
	return nil
}

func outputPathForDiff(f scanner.Finding) string {
	path := strings.ReplaceAll(f.FilePath, "/", `\`)
	if strings.TrimSpace(f.Host) == "" && strings.TrimSpace(f.Share) == "" {
		return path
	}
	return fmt.Sprintf(`\\%s\%s%s`, valueOrUnknown(f.Host), valueOrUnknown(f.Share), path)
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func scanHost(ctx context.Context, host, source string, dfsTargets []discovery.DFSTarget, checkpoints *state.Manager, recorder metrics.Recorder, cfg config.Config, engine *scanner.Engine, sink scanner.FindingSink, logger *logx.Logger) error {
	logger.Infof("scanning host %s", host)
	if observer, ok := sink.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}

	client := smb.NewClient()
	defer client.Close()

	if err := client.Connect(host, cfg.Scan.Username, cfg.Scan.Password); err != nil {
		return fmt.Errorf("%s: connect failed: %w", host, err)
	}

	shares, err := client.ListShares()
	if err != nil {
		return fmt.Errorf("%s: list shares failed: %w", host, err)
	}

	dfsHints := dfsHintsForHost(host, dfsTargets)
	if len(dfsHints) > 0 {
		logger.Infof("host %s has %d dfs-linked share hint(s)", host, len(dfsHints))
	}
	planFilters := planner.FilterOptions{
		IncludeShares: append([]string{}, cfg.Scan.Share...),
		ExcludeShares: append([]string{}, cfg.Scan.ExcludeShare...),
		IncludePaths:  append([]string{}, cfg.Scan.Path...),
		ExcludePaths:  append([]string{}, cfg.Scan.ExcludePath...),
		MaxDepth:      cfg.Scan.MaxDepth,
	}

	shareSet := make(map[string]struct{}, len(shares))
	shareInfoByName := make(map[string]smb.ShareInfo, len(shares))
	for _, share := range shares {
		key := strings.ToLower(strings.TrimSpace(share.Name))
		shareSet[key] = struct{}{}
		shareInfoByName[key] = share
	}
	for shareName := range dfsHints {
		if _, ok := shareSet[shareName]; ok {
			continue
		}
		resolvedShare := dfsHints[shareName].TargetShare
		if strings.TrimSpace(resolvedShare) == "" || !scanShareAllowed(resolvedShare, cfg.Scan) {
			continue
		}
		info := smb.ShareInfo{
			Name:        resolvedShare,
			Description: "",
			Type:        "",
		}
		shares = append(shares, info)
		shareSet[shareName] = struct{}{}
		shareInfoByName[shareName] = info
		logger.Infof("adding dfs-linked share hint %s/%s to scan plan", host, resolvedShare)
	}

	shareInputs := make([]planner.ShareInput, 0, len(shares))
	for _, shareInfo := range shares {
		share := shareInfo.Name
		if !scanShareAllowed(share, cfg.Scan) {
			logger.Debugf("skipping share %s/%s due to share filters", host, share)
			continue
		}
		if cfg.Scan.OnlyADShares && !smb.IsADShare(share) {
			continue
		}
		shareSource := source
		if _, ok := dfsHints[strings.ToLower(strings.TrimSpace(share))]; ok {
			shareSource = "dfs"
		}
		shareInputs = append(shareInputs, planner.ShareInput{
			Host:               host,
			Share:              share,
			Source:             shareSource,
			PrioritizeADShares: cfg.Scan.PrioritizeADShares,
		})
	}
	plannedShares := planner.PlanShares(shareInputs, planFilters)
	if recorder != nil {
		recorder.AddSharesEnumerated(len(plannedShares))
	}
	if cfg.Scan.OnlyADShares && len(plannedShares) == 0 {
		logger.Infof("no SYSVOL or NETLOGON shares available on %s", host)
	}

	bufferSize := cfg.Scan.WorkerCount * 2
	if bufferSize <= 0 {
		bufferSize = 2
	}

	jobs := make(chan scanner.Job, bufferSize)
	poolErrCh := make(chan error, 1)
	poolCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		poolErrCh <- scanner.NewWorkerPool(engine, sink, logger, recorder, cfg.Scan.WorkerCount).Scan(poolCtx, jobs)
	}()

	var walkErrs []error
	for _, sharePlan := range plannedShares {
		if checkpoints != nil && checkpoints.ShouldSkipShare(host, sharePlan.Share) {
			logger.Infof("resume: skipping completed share %s/%s", host, sharePlan.Share)
			continue
		}
		logger.Infof("walking %s/%s [priority=%d reason=%s]", host, sharePlan.Share, sharePlan.Priority, sharePlan.Reason)
		shareName := sharePlan.Share
		if observer, ok := sink.(scanner.ScanObserver); ok {
			observer.RecordShare(host, shareName)
		}
		dfsHint, hasDFSHint := dfsHints[strings.ToLower(strings.TrimSpace(shareName))]
		if checkpoints != nil {
			checkpoints.StartShare(host, shareName)
		}

		fileInputs := make([]planner.FileInput, 0, sharePlanningBatchSize)
		fileIndex := make(map[string]smb.RemoteFile, sharePlanningBatchSize)
		flushBatch := func() error {
			if len(fileInputs) == 0 {
				return nil
			}

			plannedFiles := planner.PlanFiles(fileInputs, planFilters)
			queuedThisBatch := 0
			for _, filePlan := range plannedFiles {
				remote, ok := fileIndex[strings.ToLower(filePlan.Path)]
				if !ok {
					continue
				}
				if checkpoints != nil && checkpoints.ShouldSkipFile(remote.Host, remote.Share, remote.Path) {
					logger.Debugf("resume: skipping completed file %s/%s/%s", remote.Host, remote.Share, remote.Path)
					continue
				}

				meta := scanner.FileMetadata{
					Host:             remote.Host,
					Share:            remote.Share,
					ShareDescription: shareInfoByName[strings.ToLower(strings.TrimSpace(remote.Share))].Description,
					ShareType:        shareInfoByName[strings.ToLower(strings.TrimSpace(remote.Share))].Type,
					FilePath:         remote.Path,
					Source:           sharePlan.Source,
					Priority:         filePlan.Priority,
					PriorityReason:   filePlan.Reason,
					Name:             remote.Name,
					Extension:        remote.Extension,
					Size:             remote.Size,
					IsDir:            remote.IsDir,
					FromSYSVOL:       strings.EqualFold(remote.Share, "SYSVOL"),
					FromNETLOGON:     strings.EqualFold(remote.Share, "NETLOGON"),
				}
				if hasDFSHint {
					meta.Source = "dfs"
					meta.DFSNamespacePath = dfsHint.NamespacePath
					meta.DFSLinkPath = dfsHint.LinkPath
				}

				remotePath := remote.Path
				job := scanner.Job{
					Metadata: meta,
					LoadContent: func(ctx context.Context, _ scanner.FileMetadata) ([]byte, error) {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						default:
						}
						return client.ReadFile(shareName, strings.ReplaceAll(remotePath, "/", `\`))
					},
					OnComplete: func(meta scanner.FileMetadata, _ scanner.Evaluation, err error) {
						if checkpoints == nil {
							return
						}
						checkpoints.RecordFileResult(meta.Host, meta.Share, meta.FilePath, err == nil)
					},
				}

				select {
				case <-poolCtx.Done():
					return poolCtx.Err()
				case jobs <- job:
					queuedThisBatch++
				}
			}

			if checkpoints != nil {
				checkpoints.AddPendingFiles(host, shareName, queuedThisBatch)
			}

			clear(fileIndex)
			fileInputs = fileInputs[:0]
			return nil
		}

		err := client.WalkShareWithOptions(shareName, smb.WalkOptions{
			IncludePaths: append([]string{}, cfg.Scan.Path...),
			ExcludePaths: append([]string{}, cfg.Scan.ExcludePath...),
			MaxDepth:     cfg.Scan.MaxDepth,
		}, func(remote smb.RemoteFile) error {
			if remote.IsDir {
				return nil
			}
			fileSource := sharePlan.Source
			if hasDFSHint {
				fileSource = "dfs"
			}
			fileInputs = append(fileInputs, planner.FileInput{
				Host:               remote.Host,
				Share:              remote.Share,
				Path:               remote.Path,
				Extension:          remote.Extension,
				Source:             fileSource,
				PrioritizeADShares: cfg.Scan.PrioritizeADShares,
			})
			fileIndex[strings.ToLower(remote.Path)] = remote
			if len(fileInputs) >= sharePlanningBatchSize {
				return flushBatch()
			}
			return nil
		})
		if err != nil {
			logger.Warnf("walk failed for %s/%s: %v", host, shareName, err)
			if checkpoints != nil {
				checkpoints.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			continue
		}
		if err := flushBatch(); err != nil {
			if checkpoints != nil {
				checkpoints.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			continue
		}
		if checkpoints != nil {
			checkpoints.FinishShareEnumeration(host, shareName)
		}
	}

	close(jobs)
	poolErr := <-poolErrCh
	if poolErr != nil {
		return poolErr
	}
	if len(walkErrs) > 0 {
		return errors.Join(walkErrs...)
	}
	return nil
}

const sharePlanningBatchSize = 2048

func scanShareAllowed(share string, cfg config.ScanConfig) bool {
	share = strings.ToLower(strings.TrimSpace(share))
	if share == "" {
		return false
	}
	if len(cfg.Share) > 0 {
		matched := false
		for _, allowed := range cfg.Share {
			if share == strings.ToLower(strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, blocked := range cfg.ExcludeShare {
		if share == strings.ToLower(strings.TrimSpace(blocked)) {
			return false
		}
	}
	return true
}

func dfsHintsForHost(host string, targets []discovery.DFSTarget) map[string]discovery.DFSTarget {
	hints := make(map[string]discovery.DFSTarget)
	host = strings.ToLower(strings.TrimSpace(host))
	for _, target := range targets {
		server := strings.ToLower(strings.TrimSpace(target.TargetServer))
		if host == "" || server == "" || host != server {
			continue
		}
		shareKey := strings.ToLower(strings.TrimSpace(target.TargetShare))
		if shareKey == "" {
			continue
		}
		if _, ok := hints[shareKey]; ok {
			continue
		}
		hints[shareKey] = target
	}
	return hints
}

func printRuleTestSummary(summary rules.TestSummary, verbose bool) {
	if len(summary.Matches) == 0 {
		fmt.Printf("No matches across %d file(s)\n", summary.FilesScanned)
		if verbose && summary.FilesSkipped > 0 {
			fmt.Printf("Skipped %d file(s) due to skip rules\n", summary.FilesSkipped)
		}
		return
	}

	for _, match := range summary.Matches {
		fmt.Printf("Rule: %s\n", match.RuleID)
		if verbose && match.RuleName != "" {
			fmt.Printf("Name: %s\n", match.RuleName)
		}
		fmt.Printf("File: %s\n", match.File)
		fmt.Printf("Match: %s\n", match.Match)
		if match.Snippet != "" {
			fmt.Printf("Snippet: %s\n", match.Snippet)
		}
		fmt.Println()
	}

	if verbose {
		fmt.Printf("Matched %d rule(s) across %d/%d file(s)\n", len(summary.Matches), summary.FilesMatched, summary.FilesScanned)
		if summary.FilesSkipped > 0 {
			fmt.Printf("Skipped %d file(s) due to skip rules\n", summary.FilesSkipped)
		}
	}
}

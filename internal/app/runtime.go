package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/discovery"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

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
	if strings.TrimSpace(opts.Profile) != "" {
		_ = config.ApplyScanProfile(cfg, opts.Profile)
	}
	if len(opts.Targets) > 0 {
		cfg.Scan.Targets = append([]string{}, opts.Targets...)
	}
	if strings.TrimSpace(opts.TargetsFile) != "" {
		cfg.Scan.TargetsFile = opts.TargetsFile
	}
	if strings.TrimSpace(opts.Profile) != "" {
		cfg.Scan.Profile = opts.Profile
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
	if strings.TrimSpace(opts.SeedManifest) != "" {
		cfg.Scan.SeedManifest = opts.SeedManifest
	}
	if opts.ValidationMode {
		cfg.Scan.ValidationMode = true
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
	if opts.NoTUI {
		cfg.Output.NoTUI = true
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
	if err := config.ApplyScanProfile(&cfg, cfg.Scan.Profile); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Scan.Username) == "" {
		return fmt.Errorf("missing SMB username: set scan.username in config or pass --username (run `snablr scan --help` for examples)")
	}
	if cfg.Scan.Password == "" {
		return fmt.Errorf("missing SMB password: set scan.password in config or pass --password (run `snablr scan --help` for examples)")
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
	if cfg.Archives.AutoZIPMaxSize < 0 {
		return fmt.Errorf("archives.auto_zip_max_size cannot be negative")
	}
	if cfg.Archives.MaxZIPSize < 0 {
		return fmt.Errorf("archives.max_zip_size cannot be negative")
	}
	if cfg.Archives.AutoTARMaxSize < 0 {
		return fmt.Errorf("archives.auto_tar_max_size cannot be negative")
	}
	if cfg.Archives.MaxTARSize < 0 {
		return fmt.Errorf("archives.max_tar_size cannot be negative")
	}
	if cfg.Archives.MaxMembers < 0 {
		return fmt.Errorf("archives.max_members cannot be negative")
	}
	if cfg.Archives.MaxMemberBytes < 0 {
		return fmt.Errorf("archives.max_member_bytes cannot be negative")
	}
	if cfg.Archives.MaxTotalUncompressed < 0 {
		return fmt.Errorf("archives.max_total_uncompressed_bytes cannot be negative")
	}
	if cfg.Archives.AllowLargeZIPs && cfg.Archives.MaxZIPSize > 0 && cfg.Archives.MaxZIPSize < cfg.Archives.AutoZIPMaxSize {
		return fmt.Errorf("archives.max_zip_size must be greater than or equal to archives.auto_zip_max_size when allow_large_zips is enabled")
	}
	if cfg.Archives.AllowLargeTARs && cfg.Archives.MaxTARSize > 0 && cfg.Archives.MaxTARSize < cfg.Archives.AutoTARMaxSize {
		return fmt.Errorf("archives.max_tar_size must be greater than or equal to archives.auto_tar_max_size when allow_large_tars is enabled")
	}
	if cfg.Suppression.SampleLimit < 0 {
		return fmt.Errorf("suppression.sample_limit cannot be negative")
	}
	seenSuppressionIDs := make(map[string]struct{}, len(cfg.Suppression.Rules))
	for idx, rule := range cfg.Suppression.Rules {
		if !rule.Enabled {
			continue
		}
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("suppression.rules[%d] is missing id", idx)
		}
		id := strings.ToLower(strings.TrimSpace(rule.ID))
		if _, ok := seenSuppressionIDs[id]; ok {
			return fmt.Errorf("duplicate suppression rule id %q", rule.ID)
		}
		seenSuppressionIDs[id] = struct{}{}
		if strings.TrimSpace(rule.Reason) == "" {
			return fmt.Errorf("suppression rule %q is missing reason", rule.ID)
		}
		if len(rule.Hosts) == 0 && len(rule.Shares) == 0 && len(rule.RuleIDs) == 0 && len(rule.Categories) == 0 && len(rule.ExactPaths) == 0 && len(rule.PathPrefixes) == 0 && len(rule.PathContains) == 0 && len(rule.Fingerprints) == 0 && len(rule.Tags) == 0 {
			return fmt.Errorf("suppression rule %q has no match criteria", rule.ID)
		}
	}
	switch strings.ToLower(cfg.Output.Format) {
	case "console", "json", "html", "all":
	default:
		return fmt.Errorf("unsupported output format %q: use console, json, html, or all", cfg.Output.Format)
	}
	if (strings.EqualFold(cfg.Output.Format, "json") || strings.EqualFold(cfg.Output.Format, "all")) && strings.TrimSpace(cfg.Output.JSONOut) == "" {
		return fmt.Errorf("output format %q requires json_out: set output.json_out or pass --json-out so Snablr knows where to write the JSON report", cfg.Output.Format)
	}
	if (strings.EqualFold(cfg.Output.Format, "html") || strings.EqualFold(cfg.Output.Format, "all")) && strings.TrimSpace(cfg.Output.HTMLOut) == "" {
		return fmt.Errorf("output format %q requires html_out: set output.html_out or pass --html-out so Snablr knows where to write the HTML report", cfg.Output.Format)
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
		return fmt.Errorf("rule id is required: pass --id <rule-id> (run `snablr rules show --help` for usage)")
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
		return fmt.Errorf("rule file is required: pass --rule <rulefile> (run `snablr rules test --help` for an example)")
	}
	if strings.TrimSpace(opts.InputFile) == "" {
		return fmt.Errorf("input file is required: pass --input <file> (run `snablr rules test --help` for an example)")
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
		return fmt.Errorf("fixtures directory is required: pass --fixtures <dir> (run `snablr rules test-dir --help` for an example)")
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

func outputPathForDiff(f scanner.Finding) string {
	path := strings.ReplaceAll(f.FilePath, "/", `\`)
	if strings.TrimSpace(f.Host) == "" && strings.TrimSpace(f.Share) == "" {
		return path
	}
	if path != "" && !strings.HasPrefix(path, `\`) {
		path = `\` + path
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

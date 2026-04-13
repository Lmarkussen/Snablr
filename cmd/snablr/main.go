package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"snablr/internal/app"
	"snablr/internal/ui"
	"snablr/internal/version"
)

func main() {
	ui.PrintBanner(os.Stdout)

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "discover":
		err = runDiscover(os.Args[2:])
	case "diff":
		err = runDiff(os.Args[2:])
	case "benchmark":
		err = runBenchmark(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	case "rules":
		err = runRules(os.Args[2:])
	case "version":
		printVersion()
		return
	case "help", "-h", "--help":
		printHelp(os.Args[2:])
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Run `snablr --help` to see the available commands and common examples.")
		fmt.Fprintln(os.Stderr)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		var exitErr *app.ExitError
		if errors.As(err, &exitErr) && exitErr.Code != 0 {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printScanUsage(fs) }

	configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
	targets := fs.String("targets", "", "Comma-separated target hosts")
	targetsFile := fs.String("targets-file", "", "Path to file containing target hosts")
	profile := fs.String("profile", "", "Scan profile: default, validation, or aggressive")

	var username string
	var password string
	fs.StringVar(&username, "username", "", "Username for SMB and LDAP authentication")
	fs.StringVar(&username, "user", "", "Alias for --username")
	fs.StringVar(&password, "password", "", "Password for SMB and LDAP authentication")
	fs.StringVar(&password, "pass", "", "Alias for --password")

	var shareFilters multiValueFlag
	var excludeShareFilters multiValueFlag
	var pathFilters multiValueFlag
	var excludePathFilters multiValueFlag
	fs.Var(&shareFilters, "share", "Limit scanning to a share name; may be repeated")
	fs.Var(&excludeShareFilters, "exclude-share", "Exclude a share name from scanning; may be repeated")
	fs.Var(&pathFilters, "path", "Limit scanning to a path prefix within a share; may be repeated")
	fs.Var(&excludePathFilters, "exclude-path", "Exclude a path prefix within a share; may be repeated")

	maxDepth := fs.Int("max-depth", 0, "Maximum directory depth to recurse within a share")
	domain := fs.String("domain", "", "Domain name override for LDAP discovery")
	rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
	workerCount := fs.Int("worker-count", 0, "Number of worker goroutines; 0 uses adaptive scaling")
	maxFileSize := fs.Int64("max-file-size", 0, "Maximum file size in bytes to scan")
	noLDAP := fs.Bool("no-ldap", false, "Disable LDAP discovery when no explicit targets are supplied")
	dc := fs.String("dc", "", "Domain controller to use for LDAP discovery")
	baseDN := fs.String("base-dn", "", "LDAP base DN to use for discovery")
	discoverDFS := fs.Bool("discover-dfs", false, "Discover DFS namespaces and linked shares")
	prioritizeADShares := fs.Bool("prioritize-ad-shares", false, "Prioritize SYSVOL and NETLOGON shares during scan planning")
	onlyADShares := fs.Bool("only-ad-shares", false, "Only scan SYSVOL and NETLOGON shares")
	baseline := fs.String("baseline", "", "Path to a previous JSON scan result to compare against")
	seedManifest := fs.String("seed-manifest", "", "Path to a seeder manifest JSON file for in-report validation summary")
	validationMode := fs.Bool("validation-mode", false, "Enable diagnostic validation logging and summary output")
	maxScanTime := fs.String("max-scan-time", "", "Maximum total scan time, for example 30m or 2h")
	checkpointFile := fs.String("checkpoint-file", "", "Path to the checkpoint JSON file")
	resume := fs.Bool("resume", false, "Resume from an existing checkpoint file")
	skipReachability := fs.Bool("skip-reachability-check", false, "Skip TCP 445 reachability testing before scanning")
	reachabilityTimeout := fs.Int("reachability-timeout", 0, "Reachability timeout in seconds")
	outputFormat := fs.String("output-format", "", "Output format: console, json, html, all, or a comma-separated combination like html,json")
	noTUI := fs.Bool("no-tui", false, "Disable the Bubble Tea live console UI and use plain stdout console output")
	jsonOut := fs.String("json-out", "", "Path to JSON output file")
	htmlOut := fs.String("html-out", "", "Path to HTML report file")
	csvOut := fs.String("csv-out", "", "Path to CSV findings export file")
	mdOut := fs.String("md-out", "", "Path to Markdown summary export file")
	credsOut := fs.String("creds-out", "", "Path to curated creds.txt export file")
	scannedTargetsOut := fs.String("scanned-targets-out", "", "Path to scanned_targets.txt audit export file")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, error")
	var wimEnabled optionalBoolFlag
	var wimAutoMaxSize optionalInt64Flag
	var wimAllowLarge optionalBoolFlag
	var wimMaxSize optionalInt64Flag
	var wimMaxMembers optionalIntFlag
	var wimMaxMemberBytes optionalInt64Flag
	var wimMaxTotalBytes optionalInt64Flag
	fs.Var(&wimEnabled, "wim-enabled", "Enable or disable WIM inspection (overrides config)")
	fs.Var(&wimAutoMaxSize, "wim-auto-max-size", "Automatic WIM inspection size limit in bytes (overrides config)")
	fs.Var(&wimAllowLarge, "wim-allow-large", "Allow WIM inspection above the automatic size limit up to --wim-max-size (overrides config)")
	fs.Var(&wimMaxSize, "wim-max-size", "Maximum WIM size in bytes allowed for inspection (overrides config)")
	fs.Var(&wimMaxMembers, "wim-max-members", "Maximum number of targeted WIM members to inspect (overrides config)")
	fs.Var(&wimMaxMemberBytes, "wim-max-member-bytes", "Maximum bytes to inspect from a single extracted WIM member (overrides config)")
	fs.Var(&wimMaxTotalBytes, "wim-max-total-bytes", "Maximum total extracted WIM bytes to inspect per image (overrides config)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	return app.RunScan(context.Background(), app.ScanOptions{
		ConfigPath:                 *configPath,
		Targets:                    parseTargets(*targets),
		TargetsFile:                *targetsFile,
		Profile:                    *profile,
		Username:                   username,
		Password:                   password,
		Share:                      append([]string{}, shareFilters...),
		ExcludeShare:               append([]string{}, excludeShareFilters...),
		Path:                       append([]string{}, pathFilters...),
		ExcludePath:                append([]string{}, excludePathFilters...),
		MaxDepth:                   *maxDepth,
		Domain:                     *domain,
		RulesDirectory:             *rulesDir,
		WorkerCount:                *workerCount,
		MaxFileSize:                *maxFileSize,
		NoLDAP:                     *noLDAP,
		DomainController:           *dc,
		BaseDN:                     *baseDN,
		DiscoverDFS:                *discoverDFS,
		PrioritizeADShares:         *prioritizeADShares,
		OnlyADShares:               *onlyADShares,
		Baseline:                   *baseline,
		SeedManifest:               *seedManifest,
		ValidationMode:             *validationMode,
		MaxScanTime:                *maxScanTime,
		CheckpointFile:             *checkpointFile,
		Resume:                     *resume,
		SkipReachabilityCheck:      *skipReachability,
		ReachabilityTimeoutSeconds: *reachabilityTimeout,
		OutputFormat:               *outputFormat,
		NoTUI:                      *noTUI,
		JSONOut:                    *jsonOut,
		HTMLOut:                    *htmlOut,
		CSVOut:                     *csvOut,
		MDOut:                      *mdOut,
		CredsOut:                   *credsOut,
		ScannedTargetsOut:          *scannedTargetsOut,
		WIMEnabled:                 wimEnabled.ptr(),
		WIMAutoMaxSize:             wimAutoMaxSize.ptr(),
		WIMAllowLarge:              wimAllowLarge.ptr(),
		WIMMaxSize:                 wimMaxSize.ptr(),
		WIMMaxMembers:              wimMaxMembers.ptr(),
		WIMMaxMemberBytes:          wimMaxMemberBytes.ptr(),
		WIMMaxTotalBytes:           wimMaxTotalBytes.ptr(),
		LogLevel:                   *logLevel,
	})
}

func runDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printDiscoverUsage(fs) }

	configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
	targets := fs.String("targets", "", "Comma-separated target hosts")
	targetsFile := fs.String("targets-file", "", "Path to file containing target hosts")

	var username string
	var password string
	fs.StringVar(&username, "username", "", "Username for LDAP and reachability discovery")
	fs.StringVar(&username, "user", "", "Alias for --username")
	fs.StringVar(&password, "password", "", "Password for LDAP discovery")
	fs.StringVar(&password, "pass", "", "Alias for --password")

	domain := fs.String("domain", "", "Domain name override for LDAP discovery")
	noLDAP := fs.Bool("no-ldap", false, "Disable LDAP discovery")
	dc := fs.String("dc", "", "Domain controller to use for LDAP discovery")
	baseDN := fs.String("base-dn", "", "LDAP base DN to use for discovery")
	discoverDFS := fs.Bool("discover-dfs", false, "Discover DFS namespaces and linked shares")
	skipReachability := fs.Bool("skip-reachability-check", false, "Skip TCP 445 reachability testing")
	reachabilityTimeout := fs.Int("reachability-timeout", 0, "Reachability timeout in seconds")
	logLevel := fs.String("log-level", "", "Log level: debug, info, warn, error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	return app.RunDiscover(context.Background(), app.DiscoverOptions{
		ConfigPath:                 *configPath,
		Targets:                    parseTargets(*targets),
		TargetsFile:                *targetsFile,
		Username:                   username,
		Password:                   password,
		Domain:                     *domain,
		NoLDAP:                     *noLDAP,
		DomainController:           *dc,
		BaseDN:                     *baseDN,
		DiscoverDFS:                *discoverDFS,
		SkipReachabilityCheck:      *skipReachability,
		ReachabilityTimeoutSeconds: *reachabilityTimeout,
		LogLevel:                   *logLevel,
	})
}

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printDiffUsage(fs) }

	oldPath := fs.String("old", "", "Path to the baseline JSON report")
	newPath := fs.String("new", "", "Path to the current JSON report")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	return app.RunDiff(app.DiffOptions{
		OldPath: *oldPath,
		NewPath: *newPath,
	})
}

func runBenchmark(args []string) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printBenchmarkUsage(fs) }

	configPath := fs.String("config", "", "Path to the benchmark YAML config file")
	dataset := fs.String("dataset", "", "Path to the local benchmark dataset directory")
	rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
	outPath := fs.String("out", "", "Path to write the benchmark JSON report")
	logLevel := fs.String("log-level", "", "Log level override")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(*configPath) == "" {
		return fmt.Errorf("benchmark config is required: pass --config <file> (run `snablr benchmark --help` for an example)")
	}

	return app.RunBenchmark(context.Background(), app.BenchmarkOptions{
		ConfigPath:     *configPath,
		Dataset:        *dataset,
		RulesDirectory: *rulesDir,
		OutPath:        *outPath,
		LogLevel:       *logLevel,
	})
}

func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printEvalUsage(fs) }

	configPath := fs.String("config", "configs/config.yaml", "Path to the Snablr YAML config file")
	dataset := fs.String("dataset", "", "Path to the local evaluation dataset directory")
	labelsPath := fs.String("labels", "", "Path to the labels YAML or JSON file")
	rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
	outPath := fs.String("out", "", "Path to write the evaluation JSON report")
	logLevel := fs.String("log-level", "", "Log level override")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	return app.RunEval(context.Background(), app.EvalOptions{
		ConfigPath:     *configPath,
		Dataset:        *dataset,
		LabelsPath:     *labelsPath,
		RulesDirectory: *rulesDir,
		OutPath:        *outPath,
		LogLevel:       *logLevel,
	})
}

func runRules(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printRulesUsage()
		return nil
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() { printRulesListUsage(fs) }
		configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
		rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
		logLevel := fs.String("log-level", "", "Log level override")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return app.RunRulesList(app.RulesOptions{
			ConfigPath:     *configPath,
			RulesDirectory: *rulesDir,
			LogLevel:       *logLevel,
		})
	case "validate":
		fs := flag.NewFlagSet("rules validate", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() { printRulesValidateUsage(fs) }
		configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
		rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
		logLevel := fs.String("log-level", "", "Log level override")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return app.RunRulesValidate(app.RulesOptions{
			ConfigPath:     *configPath,
			RulesDirectory: *rulesDir,
			LogLevel:       *logLevel,
		})
	case "show":
		fs := flag.NewFlagSet("rules show", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() { printRulesShowUsage(fs) }
		configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
		rulesDir := fs.String("rules-directory", "", "Directory containing YAML rules")
		logLevel := fs.String("log-level", "", "Log level override")
		id := fs.String("id", "", "Rule ID to display")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return app.RunRulesShow(app.RulesShowOptions{
			RulesOptions: app.RulesOptions{
				ConfigPath:     *configPath,
				RulesDirectory: *rulesDir,
				LogLevel:       *logLevel,
			},
			ID: *id,
		})
	case "test":
		fs := flag.NewFlagSet("rules test", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() { printRulesTestUsage(fs) }
		configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
		logLevel := fs.String("log-level", "", "Log level override")
		ruleFile := fs.String("rule", "", "Path to a YAML rule file")
		inputFile := fs.String("input", "", "Path to an input file")
		verbose := fs.Bool("verbose", false, "Show verbose output including snippets")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return app.RunRulesTest(app.RulesTestOptions{
			RulesOptions: app.RulesOptions{
				ConfigPath: *configPath,
				LogLevel:   *logLevel,
			},
			RuleFile:  *ruleFile,
			InputFile: *inputFile,
			Verbose:   *verbose,
		})
	case "test-dir":
		fs := flag.NewFlagSet("rules test-dir", flag.ContinueOnError)
		fs.SetOutput(os.Stdout)
		fs.Usage = func() { printRulesTestDirUsage(fs) }
		configPath := fs.String("config", "configs/config.yaml", "Path to the YAML config file")
		rulesDir := fs.String("rules", "", "Directory containing YAML rules")
		fixturesDir := fs.String("fixtures", "", "Directory containing fixture files")
		logLevel := fs.String("log-level", "", "Log level override")
		verbose := fs.Bool("verbose", false, "Show verbose output including snippets")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		return app.RunRulesTestDir(app.RulesTestDirOptions{
			RulesOptions: app.RulesOptions{
				ConfigPath:     *configPath,
				RulesDirectory: *rulesDir,
				LogLevel:       *logLevel,
			},
			FixturesDir: *fixturesDir,
			Verbose:     *verbose,
		})
	default:
		printRulesUsage()
		return fmt.Errorf("unknown rules subcommand %q", args[0])
	}
}

func parseTargets(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func printHelp(args []string) {
	if len(args) == 0 {
		printUsage()
		return
	}

	switch args[0] {
	case "scan":
		printScanUsage(flag.NewFlagSet("scan", flag.ContinueOnError))
	case "discover":
		printDiscoverUsage(flag.NewFlagSet("discover", flag.ContinueOnError))
	case "rules":
		printRulesUsage()
	case "diff":
		printDiffUsage(flag.NewFlagSet("diff", flag.ContinueOnError))
	case "benchmark":
		printBenchmarkUsage(flag.NewFlagSet("benchmark", flag.ContinueOnError))
	case "eval":
		printEvalUsage(flag.NewFlagSet("eval", flag.ContinueOnError))
	case "version":
		printVersionUsage()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Printf("Snablr %s\n\n", version.Short())
	fmt.Println("Snablr helps authorized operators discover SMB-accessible files, apply YAML rules, and review findings in console, JSON, and HTML formats.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  snablr <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan       Run SMB share triage with YAML-driven rule scanning")
	fmt.Println("  discover   Resolve targets through CLI input, LDAP, DFS, and reachability checks")
	fmt.Println("  rules      List, validate, inspect, and test rule files")
	fmt.Println("  diff       Compare two Snablr JSON result files")
	fmt.Println("  benchmark  Measure scan performance and finding volume on a local dataset")
	fmt.Println("  eval       Compare findings against a labeled local dataset")
	fmt.Println("  version    Show version, commit, and build metadata")
	fmt.Println("  help       Show top-level or command-specific help")
	fmt.Println()
	fmt.Println("Good First Steps:")
	fmt.Println("  1. snablr version")
	fmt.Println("  2. snablr scan --targets 10.0.0.5 --username USER --password PASS --output-format all --json-out results.json --html-out report.html")
	fmt.Println("  3. open report.html in a browser")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr scan --targets 10.0.0.5 --username USER --password PASS")
	fmt.Println("  snablr scan --config configs/config.yaml")
	fmt.Println("  snablr scan --username USER --password PASS")
	fmt.Println("  snablr scan --output-format all --json-out results.json --html-out report.html")
	fmt.Println("  snablr discover --discover-dfs --username USER --password PASS")
	fmt.Println("  snablr rules test --rule configs/rules/default/content.yml --input testdata/rules/fixtures/content/password-assignment.conf --verbose")
	fmt.Println("  snablr diff --old results-old.json --new results-new.json")
	fmt.Println("  snablr benchmark --config examples/eval/benchmark.yaml --out benchmark.json")
	fmt.Println("  snablr eval --dataset examples/eval/dataset --labels examples/eval/labels.yaml --out eval.json")
	fmt.Println()
	fmt.Println("Authorized use only. Run Snablr only against systems and data you are explicitly permitted to assess.")
	fmt.Println()
	fmt.Println("Use `snablr <command> --help` for command-specific flags and examples.")
}

func printScanUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr scan [options]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Runs target discovery, reachability testing, planning, SMB enumeration, rule-based scanning,")
	fmt.Println("  and report generation.")
	fmt.Println("  Required credentials for LDAP/DFS discovery are validated before the live TUI starts.")
	fmt.Println("  Discovery-based scans show target discovery and reachability progress before the TUI opens.")
	fmt.Println()
	fmt.Println("When to use it:")
	fmt.Println("  - direct target scan: use --targets or --targets-file")
	fmt.Println("  - domain-aware scan: omit targets and provide credentials so LDAP discovery can run")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr scan --targets 10.0.0.5 --username USER --password PASS")
	fmt.Println("  snablr scan --username USER --password PASS")
	fmt.Println("  snablr scan --domain example.local --dc dc01.example.local --username USER --password PASS")
	fmt.Println("  snablr scan --output-format all --json-out results.json --html-out report.html")
	fmt.Println("  snablr scan --share Finance --path Reports/ --max-depth 4")
	fmt.Println("  snablr scan --baseline previous-results.json --output-format all --json-out results.json --html-out report.html")
	fmt.Println("  snablr scan --checkpoint-file state.json --resume")
	fmt.Println("  snablr scan --wim-allow-large --wim-max-size 536870912")
	fmt.Println()
	fmt.Println("Output formats:")
	fmt.Println("  console  print findings to the terminal")
	fmt.Println("  json     write one JSON report to --json-out")
	fmt.Println("  html     write one HTML report to --html-out")
	fmt.Println("  all      print to console and write both JSON and HTML")
	fmt.Println()
	fmt.Println("Defaults:")
	fmt.Println("  --config configs/config.yaml")
	fmt.Println("  --output-format console")
	fmt.Println("  --worker-count 0 (adaptive)")
	fmt.Println("  --max-file-size 10485760")
	fmt.Println()
	fmt.Println("Results are written to the paths you provide with --json-out, --html-out, --csv-out, and --md-out.")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printDiscoverUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr discover [options]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Collects targets from explicit input, LDAP, DFS, and TCP 445 reachability checks without")
	fmt.Println("  starting an SMB file scan.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr discover --username USER --password PASS")
	fmt.Println("  snablr discover --targets fileserver01,fileserver02 --skip-reachability-check")
	fmt.Println("  snablr discover --discover-dfs --domain example.local --dc dc01.example.local --username USER --password PASS")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printDiffUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr diff --old results-old.json --new results-new.json")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Compares two Snablr JSON reports and summarizes new, removed, changed, and unchanged findings.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr diff --old baseline.json --new current.json")
	fmt.Println("  snablr diff --old weekly-results.json --new latest-results.json")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printBenchmarkUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr benchmark --config <file> [options]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Runs Snablr against an authorized local dataset and records scan duration, time to first")
	fmt.Println("  finding, files visited/read, grouped findings, and high-confidence findings.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr benchmark --config examples/eval/benchmark.yaml --out benchmark.json")
	fmt.Println("  snablr benchmark --config examples/eval/benchmark.yaml --dataset examples/eval/dataset")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printEvalUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr eval --dataset <dir> --labels <file> [options]")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Scans an authorized local dataset, compares findings to labels, and reports precision-like,")
	fmt.Println("  recall-like, noisy findings, duplicate findings, and missed rule candidates.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr eval --dataset examples/eval/dataset --labels examples/eval/labels.yaml --out eval.json")
	fmt.Println("  snablr eval --dataset examples/eval/dataset --labels examples/eval/labels.yaml --rules-directory configs/rules/default")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printRulesUsage() {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules <subcommand> [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  list       List enabled rules")
	fmt.Println("  validate   Validate rule files and regexes")
	fmt.Println("  show       Show one rule by ID")
	fmt.Println("  test       Test one rule file against one input file")
	fmt.Println("  test-dir   Test a rules directory against fixture files")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr rules list")
	fmt.Println("  snablr rules validate --config configs/config.yaml")
	fmt.Println("  snablr rules show --id content.synthetic_password")
	fmt.Println("  snablr rules test --rule configs/rules/default/content.yml --input testdata/rules/fixtures/content/password-assignment.conf --verbose")
	fmt.Println("  snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose")
}

func printRulesListUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules list [options]")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printRulesValidateUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules validate [options]")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printRulesShowUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules show --id RULE_ID [options]")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printRulesTestUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules test --rule <rulefile> --input <file> [options]")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  snablr rules test --rule configs/rules/default/content.yml --input testdata/rules/fixtures/content/password-assignment.conf --verbose")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printRulesTestDirUsage(fs *flag.FlagSet) {
	fmt.Println("Usage:")
	fmt.Println("  snablr rules test-dir --rules <dir> --fixtures <dir> [options]")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printVersionUsage() {
	fmt.Println("Usage:")
	fmt.Println("  snablr version")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Shows version, commit, and build date metadata embedded at build time.")
	fmt.Println()
	fmt.Println("If version metadata is missing, build with `make build` or use a release binary.")
}

func printVersion() {
	fmt.Println(version.String())
}

type multiValueFlag []string

func (m *multiValueFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiValueFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*m = append(*m, value)
	return nil
}

type optionalBoolFlag struct {
	set   bool
	value bool
}

func (f *optionalBoolFlag) String() string {
	if f == nil || !f.set {
		return ""
	}
	return fmt.Sprintf("%t", f.value)
}

func (f *optionalBoolFlag) Set(value string) error {
	f.set = true
	if strings.TrimSpace(value) == "" {
		f.value = true
		return nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	f.value = parsed
	return nil
}

func (f *optionalBoolFlag) IsBoolFlag() bool { return true }

func (f *optionalBoolFlag) ptr() *bool {
	if f == nil || !f.set {
		return nil
	}
	value := f.value
	return &value
}

type optionalInt64Flag struct {
	set   bool
	value int64
}

func (f *optionalInt64Flag) String() string {
	if f == nil || !f.set {
		return ""
	}
	return strconv.FormatInt(f.value, 10)
}

func (f *optionalInt64Flag) Set(value string) error {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return err
	}
	f.set = true
	f.value = parsed
	return nil
}

func (f *optionalInt64Flag) ptr() *int64 {
	if f == nil || !f.set {
		return nil
	}
	value := f.value
	return &value
}

type optionalIntFlag struct {
	set   bool
	value int
}

func (f *optionalIntFlag) String() string {
	if f == nil || !f.set {
		return ""
	}
	return strconv.Itoa(f.value)
}

func (f *optionalIntFlag) Set(value string) error {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	f.set = true
	f.value = parsed
	return nil
}

func (f *optionalIntFlag) ptr() *int {
	if f == nil || !f.set {
		return nil
	}
	value := f.value
	return &value
}

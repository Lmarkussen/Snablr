package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"snablr/internal/seed"
	"snablr/internal/version"
	"snablr/pkg/logx"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		return runVerify(args[1:])
	}

	fs := flag.NewFlagSet("snablr-seed", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printUsage(fs) }

	targets := fs.String("targets", "", "Comma-separated file server targets")
	targetsFile := fs.String("targets-file", "", "Path to file containing target hosts")

	var username string
	var password string
	fs.StringVar(&username, "username", "", "Username for SMB authentication")
	fs.StringVar(&username, "user", "", "Alias for --username")
	fs.StringVar(&password, "password", "", "Password for SMB authentication")
	fs.StringVar(&password, "pass", "", "Alias for --password")

	var shares multiValueFlag
	fs.Var(&shares, "share", "Restrict seeding to a share name; may be repeated")
	countPerCategory := fs.Int("count-per-category", 6, "Number of files to generate per category")
	maxFiles := fs.Int("max-files", 480, "Maximum total files to generate")
	depth := fs.Int("depth", 1, "Additional nested directory depth to add under each base path")
	sharesPerTarget := fs.Int("shares-per-target", 0, "Maximum number of shares to seed per target; 0 uses all accessible shares")
	likelyHitRatio := fs.Int("likely-hit-ratio", 65, "Approximate percentage of generated files intended as likely hits")
	filenameOnlyRatio := fs.Int("filename-only-ratio", 30, "Approximate percentage of generated files biased toward filename/path-only hits")
	highSeverityRatio := fs.Int("high-severity-ratio", 35, "Approximate percentage of generated files biased toward high severity")
	mediumSeverityRatio := fs.Int("medium-severity-ratio", 45, "Approximate percentage of generated files biased toward medium severity")
	dryRun := fs.Bool("dry-run", false, "Plan and manifest output only; do not write files")
	manifestOut := fs.String("manifest-out", "seed-manifest.json", "Path to manifest JSON output")
	cleanPrefix := fs.Bool("clean-prefix", false, "Remove previously seeded content under the seed prefix before writing")
	seedPrefix := fs.String("seed-prefix", "SnablrLab", "Top-level prefix to seed inside each share")
	randomSeed := fs.Int64("random-seed", 1337, "Deterministic random seed for file variation")
	logLevel := fs.String("log-level", "info", "Log level: debug, info, warn, error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	targetList, err := loadTargets(*targets, *targetsFile)
	if err != nil {
		return err
	}
	if len(targetList) == 0 {
		return fmt.Errorf("no targets supplied: use --targets or --targets-file")
	}
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("missing SMB username: pass --username")
	}
	if password == "" {
		return fmt.Errorf("missing SMB password: pass --password")
	}

	logger := logx.New(*logLevel)
	manifest, err := seed.Seed(context.Background(), seed.WriteOptions{
		Targets:             targetList,
		Username:            username,
		Password:            password,
		Shares:              append([]string{}, shares...),
		SeedPrefix:          *seedPrefix,
		DryRun:              *dryRun,
		CleanPrefix:         *cleanPrefix,
		ManifestOut:         *manifestOut,
		RandomSeed:          *randomSeed,
		Depth:               *depth,
		SharesPerTarget:     *sharesPerTarget,
		LikelyHitRatio:      *likelyHitRatio,
		FilenameOnlyRatio:   *filenameOnlyRatio,
		HighSeverityRatio:   *highSeverityRatio,
		MediumSeverityRatio: *mediumSeverityRatio,
		CountPerCat:         *countPerCategory,
		MaxFiles:            *maxFiles,
		Logf:                logger.Infof,
		Warnf:               logger.Warnf,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Snablr Seeder %s\n", version.Short())
	fmt.Printf("Entries: %d\n", len(manifest.Entries))
	fmt.Printf("Seed Prefix: %s\n", manifest.SeedPrefix)
	if *manifestOut != "" {
		fmt.Printf("Manifest: %s\n", *manifestOut)
	}
	if *dryRun {
		fmt.Println("Mode: dry-run")
	}
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("snablr-seed verify", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() { printVerifyUsage(fs) }

	manifestPath := fs.String("manifest", "", "Path to the seeder manifest JSON file")
	resultsPath := fs.String("results", "", "Path to the Snablr JSON scan result file")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if strings.TrimSpace(*manifestPath) == "" {
		return fmt.Errorf("missing manifest path: pass --manifest")
	}
	if strings.TrimSpace(*resultsPath) == "" {
		return fmt.Errorf("missing results path: pass --results")
	}

	report, err := seed.Verify(*manifestPath, *resultsPath)
	if err != nil {
		return err
	}
	seed.PrintVerificationReport(report)
	return nil
}

func loadTargets(targets, targetsFile string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}

	for _, part := range strings.Split(targets, ",") {
		add(part)
	}
	if strings.TrimSpace(targetsFile) != "" {
		data, err := os.ReadFile(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("read targets file %s: %w", targetsFile, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
	}
	return out, nil
}

func printUsage(fs *flag.FlagSet) {
	fmt.Printf("Snablr Seeder %s\n\n", version.Short())
	fmt.Println("Usage:")
	fmt.Println("  snablr-seed [options]")
	fmt.Println("  snablr-seed verify --manifest seed-manifest.json --results results.json")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Generates synthetic lab files and writes them under a controlled prefix on accessible SMB shares.")
	fmt.Println("  The seeder uses only obviously fake content for authorized test environments.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  snablr-seed --targets fs01 --username USER --password PASS --dry-run")
	fmt.Println("  snablr-seed --targets fs01,fs02 --username USER --password PASS --manifest-out seed-manifest.json")
	fmt.Println("  snablr-seed --targets fs01 --username USER --password PASS --share Finance --clean-prefix")
	fmt.Println("  snablr-seed --targets 172.16.0.80,172.16.0.90 --username USER --password PASS --count-per-category 24 --max-files 1200 --depth 3 --shares-per-target 2")
	fmt.Println("  snablr-seed --targets fs01 --username USER --password PASS --likely-hit-ratio 35 --filename-only-ratio 20")
	fmt.Println("  snablr-seed --targets fs01 --username USER --password PASS --likely-hit-ratio 85 --high-severity-ratio 60 --medium-severity-ratio 25")
	fmt.Println("  snablr-seed --targets fs01 --username USER --password PASS --seed-prefix SnablrLab --random-seed 20260315")
	fmt.Println("  snablr-seed verify --manifest seed-manifest.json --results results.json")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
}

func printVerifyUsage(fs *flag.FlagSet) {
	fmt.Printf("Snablr Seeder %s\n\n", version.Short())
	fmt.Println("Usage:")
	fmt.Println("  snablr-seed verify --manifest seed-manifest.json --results results.json")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Compares the lab seeder manifest to a Snablr JSON scan result and reports expected items found,")
	fmt.Println("  expected items missed, unexpected findings, and coverage by category.")
	fmt.Println()
	fmt.Println("Flags:")
	fs.PrintDefaults()
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

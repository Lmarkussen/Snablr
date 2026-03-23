package seed

import (
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

func TestGenerateRespectsScaleDepthAndExpectedSignals(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 4,
		MaxFiles:         50,
		Depth:            2,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(files) != 50 {
		t.Fatalf("expected 50 files, got %d", len(files))
	}

	foundNested := false
	foundSignals := false
	uniqueFilenames := make(map[string]struct{})
	for _, file := range files {
		if len(file.ExpectedSignalTypes) > 0 {
			foundSignals = true
		}
		if file.RelativePath != "" && file.RelativePath != "SnablrLab" {
			foundNested = true
		}
		uniqueFilenames[file.Filename] = struct{}{}
	}
	if !foundNested {
		t.Fatalf("expected nested relative paths in generated files")
	}
	if !foundSignals {
		t.Fatalf("expected generated files to include expected signal types")
	}
	if len(uniqueFilenames) < 10 {
		t.Fatalf("expected diverse generated filenames, got %d unique names", len(uniqueFilenames))
	}
}

func TestGenerateSupportsIntentAndSignalTuning(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory:    2,
		MaxFiles:            20,
		SeedPrefix:          "SnablrLab",
		RandomSeed:          20260316,
		LikelyHitRatio:      0,
		FilenameOnlyRatio:   100,
		HighSeverityRatio:   0,
		MediumSeverityRatio: 100,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected generated files")
	}

	foundPossibleOrNoise := false
	foundFilenameOnly := false
	foundMedium := false

	for _, file := range files {
		if file.IntendedAs == "possible-hit" || file.IntendedAs == "filler/noise" {
			foundPossibleOrNoise = true
		}
		hasContentSignal := false
		for _, signalType := range file.ExpectedSignalTypes {
			if signalType == "content" {
				hasContentSignal = true
				break
			}
		}
		if !hasContentSignal {
			foundFilenameOnly = true
		}
		if file.ExpectedSeverity == "medium" {
			foundMedium = true
		}
	}

	if !foundPossibleOrNoise {
		t.Fatalf("expected tuned generation to include non-likely files")
	}
	if !foundFilenameOnly {
		t.Fatalf("expected tuned generation to include filename-only variants")
	}
	if !foundMedium {
		t.Fatalf("expected tuned generation to include medium severity variants")
	}
}

func TestGenerateProducesUniquePathsAtLargerScale(t *testing.T) {
	t.Parallel()

	categoryCount := len(defaultTemplates())
	files, err := Generate(GenerateOptions{
		CountPerCategory: 25,
		MaxFiles:         500,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	expected := categoryCount * 25
	if expected > 500 {
		expected = 500
	}
	if len(files) != expected {
		t.Fatalf("expected %d files, got %d", expected, len(files))
	}

	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		fullPath := FullPath(file)
		if _, ok := seen[fullPath]; ok {
			t.Fatalf("expected unique generated paths, found duplicate %s", fullPath)
		}
		seen[fullPath] = struct{}{}
	}
}

func TestGenerateDatabaseSeedPackIncludesMixedExpectedClasses(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         400,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	triageClasses := make(map[string]int)
	detectionClasses := make(map[string]int)
	foundDatabaseCategory := false
	foundActionableConfig := false
	foundConfigOnly := false
	foundWeakReview := false
	foundArtifact := false
	foundCorrelated := false

	for _, file := range files {
		if file.Category != "database" {
			continue
		}
		foundDatabaseCategory = true
		if file.ExpectedClass != "" {
			detectionClasses[file.ExpectedClass]++
		}
		if file.ExpectedTriageClass != "" {
			triageClasses[file.ExpectedTriageClass]++
		}
		name := strings.ToLower(file.Filename)
		switch {
		case name == "appsettings.json" || name == "web.config" || name == ".env" || strings.HasSuffix(name, ".dsn"):
			if file.ExpectedClass == seedClassActionable || file.ExpectedClass == seedClassCorrelatedHighConfidence {
				foundActionableConfig = true
			}
		case name == "database.yml" || name == "application.properties" || name == "config.php" || name == "k8s-db-secret.yaml":
			if file.ExpectedClass == seedClassConfigOnly {
				foundConfigOnly = true
			}
		case name == "db-admin-notes.txt" || name == "deploy-db.py":
			if file.ExpectedClass == seedClassWeakReview {
				foundWeakReview = true
			}
		case strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".dump") || strings.HasSuffix(name, ".dmp") || strings.HasSuffix(name, ".sqlite") || strings.HasSuffix(name, ".mdb"):
			if file.ExpectedClass == seedClassActionable {
				foundArtifact = true
			}
		case name == "docker-compose.yml" || name == "odbc.ini":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated && file.ExpectedConfidence == "high" {
				foundCorrelated = true
			}
		}
	}

	if !foundDatabaseCategory {
		t.Fatal("expected generated corpus to include database category files")
	}
	for _, expected := range []string{seedClassConfigOnly, seedClassWeakReview, seedClassActionable, seedClassCorrelatedHighConfidence} {
		if detectionClasses[expected] == 0 {
			t.Fatalf("expected database seed pack to include detection class %q, got %+v", expected, detectionClasses)
		}
	}
	for _, expected := range []string{seedTriageActionable, seedTriageConfigOnly, seedTriageWeakReview} {
		if triageClasses[expected] == 0 {
			t.Fatalf("expected database seed pack to include triage class %q, got %+v", expected, triageClasses)
		}
	}
	if !foundActionableConfig {
		t.Fatalf("expected actionable database configuration samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundConfigOnly {
		t.Fatalf("expected config-only database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundWeakReview {
		t.Fatalf("expected weak-review database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundArtifact {
		t.Fatalf("expected database artifact or backup samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundCorrelated {
		t.Fatalf("expected correlated high-confidence database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
}

func TestGenerateSecretStoreSeedPackIncludesActionableArtifacts(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 12,
		MaxFiles:         240,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundNTDS := false
	foundShadow := false
	foundSystem := false
	foundSecurity := false
	foundNTDSBackup := false
	foundHiveBackup := false
	foundDecoy := false

	for _, file := range files {
		if file.Category != "secret-stores" {
			continue
		}
		name := strings.ToLower(file.Filename)
		switch name {
		case "ntds.dit":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundNTDS = true
			}
		case "ntds.dit.bak":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundNTDSBackup = true
			}
		case "shadow":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundShadow = true
			}
		case "system":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSystem = true
			}
		case "security":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSecurity = true
			}
		case "system.bak":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundHiveBackup = true
			}
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		case "security.old":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundHiveBackup = true
			}
		case "shadow-notes.txt":
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		case "system.txt":
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		}
	}

	if !foundNTDS {
		t.Fatal("expected secret-store seed pack to include actionable NTDS.DIT artifact")
	}
	if !foundShadow {
		t.Fatal("expected secret-store seed pack to include actionable shadow artifact")
	}
	if !foundSystem {
		t.Fatal("expected secret-store seed pack to include actionable SYSTEM hive artifact")
	}
	if !foundSecurity {
		t.Fatal("expected secret-store seed pack to include actionable SECURITY hive artifact")
	}
	if !foundNTDSBackup {
		t.Fatal("expected secret-store seed pack to include actionable NTDS.DIT.bak artifact")
	}
	if !foundHiveBackup {
		t.Fatal("expected secret-store seed pack to include actionable hive backup artifact")
	}
	if !foundDecoy {
		t.Fatal("expected secret-store seed pack to include benign decoys")
	}
}

func TestGenerateADCorrelationSeedPackIncludesCorrelatedAnchor(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 12,
		MaxFiles:         320,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCorrelatedNTDS := false
	foundSupportingSystem := false

	for _, file := range files {
		if file.Category != "ad-correlation" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "ntds.dit":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated && file.ExpectedConfidence == "high" {
				foundCorrelatedNTDS = true
			}
		case "system":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSupportingSystem = true
			}
		}
	}

	if !foundCorrelatedNTDS {
		t.Fatal("expected ad-correlation seed pack to include correlated NTDS.DIT anchor")
	}
	if !foundSupportingSystem {
		t.Fatal("expected ad-correlation seed pack to include supporting SYSTEM artifact")
	}
}

func TestGenerateZIPSeedPackIncludesPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         500,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCorrelated := false
	foundActionable := false
	foundConfigOnly := false
	foundBinaryNoise := false
	foundNestedNoise := false
	foundOversized := false

	for _, file := range files {
		if file.Category != "zip-archives" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "deploy-package.zip":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedPath == "SnablrLab/Deploy/deploy-package.zip!.env" {
				foundCorrelated = true
			}
		case "legacy-configs.zip", "deployment-recovery.zip":
			if file.ExpectedClass == seedClassActionable && strings.Contains(file.ExpectedPath, ".zip!") {
				foundActionable = true
			}
		case "old-config-bundle.zip":
			if file.ExpectedClass == seedClassConfigOnly && strings.Contains(file.ExpectedPath, ".zip!") {
				foundConfigOnly = true
			}
		case "binary-media-bundle.zip":
			if file.IntendedAs == "filler/noise" {
				foundBinaryNoise = true
			}
		case "nested-export-bundle.zip":
			if file.IntendedAs == "filler/noise" {
				foundNestedNoise = true
			}
		case "oversized-config-export.zip":
			if file.IntendedAs == "filler/noise" && len(file.Content) > 10*1024*1024 {
				foundOversized = true
			}
		}
	}

	if !foundCorrelated {
		t.Fatal("expected zip seed pack to include correlated archive detection case")
	}
	if !foundActionable {
		t.Fatal("expected zip seed pack to include actionable archive detection case")
	}
	if !foundConfigOnly {
		t.Fatal("expected zip seed pack to include config-only archive case")
	}
	if !foundBinaryNoise {
		t.Fatal("expected zip seed pack to include binary-only negative archive case")
	}
	if !foundNestedNoise {
		t.Fatal("expected zip seed pack to include nested-archive negative case")
	}
	if !foundOversized {
		t.Fatal("expected zip seed pack to include oversized archive case")
	}
}

func TestGeneratedZIPSeedProducesArchiveFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         500,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var archiveSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && file.ExpectedPath != "" && strings.EqualFold(file.Filename, "deploy-package.zip") {
			archiveSeed = file
			break
		}
	}
	if archiveSeed == nil {
		t.Fatal("expected generated zip archive seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*archiveSeed),
		Name:      archiveSeed.Filename,
		Extension: ".zip",
		Size:      int64(len(archiveSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, archiveSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated zip seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == archiveSeed.ExpectedPath && finding.ArchivePath == FullPath(*archiveSeed) && finding.ArchiveMemberPath == ".env" {
			foundExpectedPath = true
			break
		}
	}
	if !foundExpectedPath {
		t.Fatalf("expected archive finding path %q, got %#v", archiveSeed.ExpectedPath, evaluation.Findings)
	}
}

func TestGeneratedOversizedZIPSeedIsSkippedByDefault(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         500,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var oversized *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && strings.EqualFold(file.Filename, "oversized-config-export.zip") {
			oversized = file
			break
		}
	}
	if oversized == nil {
		t.Fatal("expected oversized zip seed")
	}

	engine := scanner.NewEngine(scanner.Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*oversized),
		Name:      oversized.Filename,
		Extension: ".zip",
		Size:      int64(len(oversized.Content)),
	}

	evaluation := engine.Evaluate(meta, oversized.Content)
	if !evaluation.Skipped || !strings.Contains(evaluation.SkipReason, "automatic inspection limit") {
		t.Fatalf("expected oversized zip seed to be skipped by default, got %#v", evaluation)
	}
}

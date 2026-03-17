package seed

import (
	"strings"
	"testing"
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

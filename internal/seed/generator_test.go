package seed

import "testing"

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

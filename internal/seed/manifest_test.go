package seed

import (
	"path/filepath"
	"testing"
)

func TestManifestRoundTripsExpectedTriageClass(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	manifest := Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []SeedManifestEntry{
			{
				Host:                "fs01",
				Share:               "SQL",
				Path:                "SnablrLab/SQL/appsettings.json",
				Category:            "database",
				Format:              "json",
				IntendedAs:          "likely-hit",
				ExpectedClass:       seedClassCorrelatedHighConfidence,
				ExpectedTriageClass: seedTriageActionable,
				ExpectedConfidence:  "high",
				ExpectedCorrelated:  true,
				ExpectedSignalTypes: []string{"content", "filename"},
				ExpectedSeverity:    "high",
				Status:              "written",
			},
		},
	}

	if err := manifest.Write(path); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected one manifest entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].ExpectedClass != seedClassCorrelatedHighConfidence {
		t.Fatalf("expected detection class %q, got %+v", seedClassCorrelatedHighConfidence, loaded.Entries[0])
	}
	if loaded.Entries[0].ExpectedTriageClass != seedTriageActionable {
		t.Fatalf("expected triage class %q, got %+v", seedTriageActionable, loaded.Entries[0])
	}
	if loaded.Entries[0].ExpectedConfidence != "high" || !loaded.Entries[0].ExpectedCorrelated {
		t.Fatalf("expected high-confidence correlated manifest entry, got %+v", loaded.Entries[0])
	}
}

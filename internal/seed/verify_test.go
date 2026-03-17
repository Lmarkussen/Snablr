package seed

import (
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/scanner"
)

func TestVerifyReportsFoundMissedUnexpectedAndCoverage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	resultsPath := filepath.Join(dir, "results.json")

	manifest := Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []SeedManifestEntry{
			{
				Host:                "fs01",
				Share:               "Finance",
				Path:                "SnablrLab/Finance/payroll_export_001.csv",
				Category:            "payroll",
				ExpectedSignalTypes: []string{"content", "filename"},
			},
			{
				Host:                "fs01",
				Share:               "Config",
				Path:                "SnablrLab/Config/appsettings_001.conf",
				Category:            "config",
				ExpectedSignalTypes: []string{"content"},
			},
			{
				Host:                "fs01",
				Share:               "Temp",
				Path:                "SnablrLab/Temp/readme.txt",
				Category:            "noise",
				IntendedAs:          "filler/noise",
				ExpectedSignalTypes: []string{"filename"},
			},
		},
	}
	if err := manifest.Write(manifestPath); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	results := []byte(`{
  "findings": [
	    {
	      "host": "fs01",
	      "share": "Finance",
	      "file_path": "SnablrLab/Finance/payroll_export_001.csv",
	      "rule_id": "filename.payroll",
	      "rule_name": "Payroll File",
	      "severity": "high",
	      "category": "business-data",
	      "signal_type": "filename"
	    },
    {
      "host": "fs01",
      "share": "Web",
      "file_path": "SnablrLab/Web/unexpected.conf",
      "rule_id": "content.secret",
      "rule_name": "Secret",
      "severity": "medium",
      "category": "credentials"
    }
  ]
}`)
	if err := os.WriteFile(resultsPath, results, 0o644); err != nil {
		t.Fatalf("write results: %v", err)
	}

	report, err := Verify(manifestPath, resultsPath)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if report.ExpectedItems != 2 || report.FoundItems != 1 || report.MissedItems != 1 || report.UnexpectedFindings != 1 {
		t.Fatalf("unexpected summary: %+v", report)
	}
	if report.FillerItems != 1 || report.FillerMatchedItems != 0 || report.FillerMissedItems != 1 {
		t.Fatalf("unexpected filler summary: %+v", report)
	}
	if len(report.Coverage) != 2 {
		t.Fatalf("expected 2 coverage entries, got %+v", report.Coverage)
	}
	if len(report.SignalCoverage) != 2 {
		t.Fatalf("expected 2 signal coverage entries, got %+v", report.SignalCoverage)
	}
	if report.SignalCoverage[0].Expected+report.SignalCoverage[1].Expected != 3 {
		t.Fatalf("expected aggregate signal coverage count 3, got %+v", report.SignalCoverage)
	}
	foundBySignal := make(map[string]int, len(report.SignalCoverage))
	for _, summary := range report.SignalCoverage {
		foundBySignal[summary.SignalType] = summary.Found
	}
	if foundBySignal["filename"] != 1 {
		t.Fatalf("expected filename signal coverage to record one found item, got %+v", report.SignalCoverage)
	}
}

func TestVerifySummarizesExpectedSeedClasses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	resultsPath := filepath.Join(dir, "results.json")

	manifest := Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []SeedManifestEntry{
			{
				Host:          "fs01",
				Share:         "Config",
				Path:          "SnablrLab/Config/database.yml",
				Category:      "database",
				ExpectedClass: seedClassConfigOnly,
			},
			{
				Host:               "fs01",
				Share:              "Config",
				Path:               "SnablrLab/Config/config.php",
				Category:           "database",
				ExpectedClass:      seedClassConfigOnly,
				ExpectedConfidence: "low",
			},
			{
				Host:               "fs01",
				Share:              "Deploy",
				Path:               "SnablrLab/Deploy/deploy-db.py",
				Category:           "database",
				ExpectedClass:      seedClassWeakReview,
				ExpectedConfidence: "medium",
			},
			{
				Host:               "fs01",
				Share:              "SQL",
				Path:               "SnablrLab/SQL/finance-prod.dsn",
				Category:           "database",
				ExpectedClass:      seedClassActionable,
				ExpectedConfidence: "high",
			},
			{
				Host:               "fs01",
				Share:              "Deploy",
				Path:               "SnablrLab/Deploy/appsettings.json",
				Category:           "database",
				ExpectedClass:      seedClassCorrelatedHighConfidence,
				ExpectedConfidence: "high",
				ExpectedCorrelated: true,
			},
		},
	}
	if err := manifest.Write(manifestPath); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	results := []byte(`{
  "findings": [
    {
      "host": "fs01",
      "share": "Config",
      "file_path": "SnablrLab/Config/config.php",
      "rule_id": "dbinspect.infrastructure.connection_string",
      "rule_name": "Validated Database Server Indicator",
      "severity": "low",
      "confidence": "low",
      "category": "configuration",
      "signal_type": "validated",
      "triage_class": "config-only",
      "actionable": false,
      "correlated": false
    },
    {
      "host": "fs01",
      "share": "Deploy",
      "file_path": "SnablrLab/Deploy/deploy-db.py",
      "rule_id": "dbinspect.infrastructure.connection_string",
      "rule_name": "Validated Database Server Indicator",
      "severity": "medium",
      "confidence": "medium",
      "category": "scripts",
      "signal_type": "validated",
      "triage_class": "weak-review",
      "actionable": false,
      "correlated": false
    },
    {
      "host": "fs01",
      "share": "SQL",
      "file_path": "SnablrLab/SQL/finance-prod.dsn",
      "rule_id": "dbinspect.access.dsn",
      "rule_name": "Validated Database DSN Credentials",
      "severity": "high",
      "confidence": "high",
      "category": "database-access",
      "signal_type": "validated",
      "triage_class": "actionable",
      "actionable": true,
      "correlated": false
    },
    {
      "host": "fs01",
      "share": "Deploy",
      "file_path": "SnablrLab/Deploy/appsettings.json",
      "rule_id": "dbinspect.access.connection_string",
      "rule_name": "Validated Database Connection Details",
      "severity": "high",
      "confidence": "high",
      "category": "database-access",
      "signal_type": "validated",
      "triage_class": "actionable",
      "actionable": true,
      "correlated": true
    }
  ]
}`)
	if err := os.WriteFile(resultsPath, results, 0o644); err != nil {
		t.Fatalf("write results: %v", err)
	}

	report, err := Verify(manifestPath, resultsPath)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	coverageByClass := make(map[string]ExpectedClassSummary, len(report.ClassCoverage))
	for _, summary := range report.ClassCoverage {
		coverageByClass[summary.ExpectedClass] = summary
	}

	configOnly := coverageByClass[seedClassConfigOnly]
	if configOnly.Planted != 2 || configOnly.Matched != 2 || configOnly.Suppressed != 1 || configOnly.Downgraded != 1 || configOnly.Mismatched != 0 {
		t.Fatalf("unexpected config-only summary: %+v", configOnly)
	}
	weakReview := coverageByClass[seedClassWeakReview]
	if weakReview.Planted != 1 || weakReview.Downgraded != 1 || weakReview.Mismatched != 0 {
		t.Fatalf("unexpected weak-review summary: %+v", weakReview)
	}
	actionable := coverageByClass[seedClassActionable]
	if actionable.Planted != 1 || actionable.Promoted != 1 || actionable.Mismatched != 0 {
		t.Fatalf("unexpected actionable summary: %+v", actionable)
	}
	correlated := coverageByClass[seedClassCorrelatedHighConfidence]
	if correlated.Planted != 1 || correlated.Promoted != 1 || correlated.Mismatched != 0 {
		t.Fatalf("unexpected correlated summary: %+v", correlated)
	}

	if len(report.SuppressedConfigOnly) != 2 {
		t.Fatalf("expected two config-only successes, got %+v", report.SuppressedConfigOnly)
	}
	if len(report.PromotedActionable) != 1 || report.PromotedActionable[0].Entry.Path != "SnablrLab/SQL/finance-prod.dsn" {
		t.Fatalf("expected actionable promotion entry, got %+v", report.PromotedActionable)
	}
	if len(report.PromotedCorrelated) != 1 || !report.PromotedCorrelated[0].ObservedCorrelated {
		t.Fatalf("expected correlated promotion entry, got %+v", report.PromotedCorrelated)
	}
	if len(report.ClassMismatches) != 0 {
		t.Fatalf("expected no class mismatches, got %+v", report.ClassMismatches)
	}
}

func TestVerifyFindingsMatchesInMemoryResults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	manifest := Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []SeedManifestEntry{
			{
				Host:          "fs01",
				Share:         "SQL",
				Path:          "SnablrLab/SQL/app.dsn",
				Category:      "database",
				ExpectedClass: seedClassActionable,
			},
			{
				Host:          "fs01",
				Share:         "Config",
				Path:          "SnablrLab/Config/database.yml",
				Category:      "database",
				ExpectedClass: seedClassConfigOnly,
			},
		},
	}
	if err := manifest.Write(manifestPath); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	report, err := VerifyFindings(manifestPath, []scanner.Finding{
		{
			Host:        "fs01",
			Share:       "SQL",
			FilePath:    "SnablrLab/SQL/app.dsn",
			Category:    "database-access",
			Severity:    "high",
			Confidence:  "high",
			TriageClass: "actionable",
			Actionable:  true,
			Correlated:  false,
			SignalType:  "validated",
		},
	})
	if err != nil {
		t.Fatalf("VerifyFindings returned error: %v", err)
	}
	if report.ExpectedItems != 2 || report.FoundItems != 1 || report.MissedItems != 1 {
		t.Fatalf("unexpected verification summary: %+v", report)
	}
}

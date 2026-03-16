package seed

import (
	"os"
	"path/filepath"
	"testing"
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

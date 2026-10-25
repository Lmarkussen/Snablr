package seed

import (
	"errors"
	"fmt"
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
		SeedPrefix: "SyntheticSeed",
		Entries: []SeedManifestEntry{
			{
				Host:                "fileserver01",
				Share:               "Finance",
				Path:                "SyntheticSeed/Finance/payroll_export_001.csv",
				Category:            "payroll",
				ExpectedSignalTypes: []string{"content", "filename"},
			},
			{
				Host:                "fileserver01",
				Share:               "Config",
				Path:                "SyntheticSeed/Config/appsettings_001.conf",
				Category:            "config",
				ExpectedSignalTypes: []string{"content"},
			},
			{
				Host:                "fileserver01",
				Share:               "Temp",
				Path:                "SyntheticSeed/Temp/readme.txt",
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
	      "host": "fileserver01",
	      "share": "Finance",
	      "file_path": "SyntheticSeed/Finance/payroll_export_001.csv",
	      "rule_id": "filename.payroll",
	      "rule_name": "Payroll File",
	      "severity": "high",
	      "category": "business-data",
	      "signal_type": "filename"
	    },
    {
      "host": "fileserver01",
      "share": "Web",
      "file_path": "SyntheticSeed/Web/unexpected.conf",
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

func TestVerifyDoesNotMissZeroObservationNegativeEntries(t *testing.T) {
	manifest := Manifest{SeedPrefix: "SyntheticSeed", Entries: []SeedManifestEntry{
		{Host: "fileserver01", Share: "Docs", Path: "SyntheticSeed/Docs/policy.txt", Category: "noise", ExpectedClass: "negative", NegativeReason: "policy text"},
		{Host: "fileserver01", Share: "Docs", Path: "SyntheticSeed/Docs/ambiguous.txt", Category: "review", ExpectedClass: "review", NegativeReason: "ambiguous relationship"},
		{Host: "fileserver01", Share: "Docs", Path: "SyntheticSeed/Docs/unsupported.csv", Category: "documents", ExpectedClass: "unsupported", SupportStatus: "unsupported"},
	}}
	report := verifyFindings("manifest.json", []scanner.Finding{{
		Host: "fileserver01", Share: "Docs", FilePath: "SyntheticSeed/Docs/policy.txt", RuleID: "content.credential_note_indicators",
	}}, manifest)
	if report.MissedItems != 0 || report.ExpectedItems != 0 || report.UnexpectedFindings != 1 {
		t.Fatalf("zero-observation entries were treated as expected findings: %+v", report)
	}
}

func TestVerifySummarizesExpectedSeedClasses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	resultsPath := filepath.Join(dir, "results.json")

	manifest := Manifest{
		SeedPrefix: "SyntheticSeed",
		Entries: []SeedManifestEntry{
			{
				Host:          "fileserver01",
				Share:         "Config",
				Path:          "SyntheticSeed/Config/database.yml",
				Category:      "database",
				ExpectedClass: seedClassConfigOnly,
			},
			{
				Host:               "fileserver01",
				Share:              "Config",
				Path:               "SyntheticSeed/Config/config.php",
				Category:           "database",
				ExpectedClass:      seedClassConfigOnly,
				ExpectedConfidence: "low",
			},
			{
				Host:               "fileserver01",
				Share:              "Deploy",
				Path:               "SyntheticSeed/Deploy/deploy-db.py",
				Category:           "database",
				ExpectedClass:      seedClassWeakReview,
				ExpectedConfidence: "medium",
			},
			{
				Host:               "fileserver01",
				Share:              "SQL",
				Path:               "SyntheticSeed/SQL/finance-prod.dsn",
				Category:           "database",
				ExpectedClass:      seedClassActionable,
				ExpectedConfidence: "high",
			},
			{
				Host:               "fileserver01",
				Share:              "Deploy",
				Path:               "SyntheticSeed/Deploy/appsettings.json",
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
      "host": "fileserver01",
      "share": "Config",
      "file_path": "SyntheticSeed/Config/config.php",
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
      "host": "fileserver01",
      "share": "Deploy",
      "file_path": "SyntheticSeed/Deploy/deploy-db.py",
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
      "host": "fileserver01",
      "share": "SQL",
      "file_path": "SyntheticSeed/SQL/finance-prod.dsn",
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
      "host": "fileserver01",
      "share": "Deploy",
      "file_path": "SyntheticSeed/Deploy/appsettings.json",
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
	if len(report.PromotedActionable) != 1 || report.PromotedActionable[0].Entry.Path != "SyntheticSeed/SQL/finance-prod.dsn" {
		t.Fatalf("expected actionable promotion entry, got %+v", report.PromotedActionable)
	}
	if len(report.PromotedCorrelated) != 1 || !report.PromotedCorrelated[0].ObservedCorrelated {
		t.Fatalf("expected correlated promotion entry, got %+v", report.PromotedCorrelated)
	}
	if len(report.ClassMismatches) != 0 {
		t.Fatalf("expected no class mismatches, got %+v", report.ClassMismatches)
	}
}

func TestNormalizeVerifyPathHandlesWIMAndSQLiteVirtualPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"SyntheticSeed/Deploy/image.wim!Windows/Panther/unattend.xml", "syntheticseed/deploy/image.wim!windows/panther/unattend.xml"},
		{"SyntheticSeed/Deploy/image.wim[index=1]!Windows/Panther/unattend.xml", "syntheticseed/deploy/image.wim!windows/panther/unattend.xml"},
		{"SyntheticSeed/Apps/customers-prod.sqlite::users.password", "syntheticseed/apps/customers-prod.sqlite"},
		{"SyntheticSeed/Apps/customers-prod.sqlite", "syntheticseed/apps/customers-prod.sqlite"},
	}

	for _, test := range tests {
		if got := normalizeVerifyPath(test.in); got != test.want {
			t.Fatalf("normalizeVerifyPath(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestVerifyMatchesArchiveFindingPaths(t *testing.T) {
	t.Parallel()

	manifest := Manifest{
		SeedPrefix: "SyntheticSeed",
		Entries: []SeedManifestEntry{
			{
				Host:               "fileserver01",
				Share:              "Deploy",
				Path:               "SyntheticSeed/Deploy/deploy-package.zip!.env",
				Category:           "zip-archives",
				ExpectedClass:      seedClassCorrelatedHighConfidence,
				ExpectedConfidence: "high",
				ExpectedCorrelated: true,
			},
		},
	}

	report := verifyFindings("manifest.json", []scanner.Finding{
		{
			Host:              "fileserver01",
			Share:             "Deploy",
			FilePath:          "SyntheticSeed/Deploy/deploy-package.zip!.env",
			ArchivePath:       "SyntheticSeed/Deploy/deploy-package.zip",
			ArchiveMemberPath: ".env",
			RuleID:            "content.password_assignment_indicators",
			RuleName:          "Password Assignment Indicators",
			Severity:          "high",
			Confidence:        "high",
			Category:          "credentials",
			TriageClass:       "actionable",
			Actionable:        true,
			Correlated:        true,
			SignalType:        "content",
		},
	}, manifest)

	if report.ExpectedItems != 1 || report.FoundItems != 1 || report.MissedItems != 0 {
		t.Fatalf("expected archive finding to verify cleanly, got %+v", report)
	}
	if len(report.PromotedCorrelated) != 1 {
		t.Fatalf("expected correlated archive promotion in verification summary, got %+v", report.PromotedCorrelated)
	}
}

func TestVerifyTreatsCredentialGroundTruthAsActionable(t *testing.T) {
	t.Parallel()

	manifest := Manifest{
		SeedPrefix: "SyntheticSeed",
		Entries: []SeedManifestEntry{{
			Host: "fileserver01", Share: "Docs", Path: "SyntheticSeed/Docs/credentials.txt",
			Category: "credentials-v2", ExpectedClass: seedClassCredential,
			ExpectedConfidence: "medium",
		}},
	}
	report := verifyFindings("manifest.json", []scanner.Finding{{
		Host: "fileserver01", Share: "Docs", FilePath: "SyntheticSeed/Docs/credentials.txt",
		Category: "credentials", TriageClass: "actionable", Actionable: true,
		Confidence: "high", Severity: "high",
	}}, manifest)

	if report.MissedItems != 0 || len(report.ClassMismatches) != 0 || report.ClassCoverage[0].Matched != 1 {
		t.Fatalf("credential ground truth should verify as actionable: %+v", report)
	}
}

func TestVerifyFindingsMatchesInMemoryResults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")

	manifest := Manifest{
		SeedPrefix: "SyntheticSeed",
		Entries: []SeedManifestEntry{
			{
				Host:          "fileserver01",
				Share:         "SQL",
				Path:          "SyntheticSeed/SQL/app.dsn",
				Category:      "database",
				ExpectedClass: seedClassActionable,
			},
			{
				Host:          "fileserver01",
				Share:         "Config",
				Path:          "SyntheticSeed/Config/database.yml",
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
			Host:        "fileserver01",
			Share:       "SQL",
			FilePath:    "SyntheticSeed/SQL/app.dsn",
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

func TestVerifyFindingIteratorSummaryMatchesLegacyCounts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	manifest := Manifest{Entries: []SeedManifestEntry{
		{Host: "host", Share: "share", Path: "root/positive.txt", Category: "credentials", ExpectedClass: seedClassCredential, ExpectedSignalTypes: []string{"content"}},
		{Host: "host", Share: "share", Path: "root/missing.txt", Category: "credentials", ExpectedClass: seedClassActionable},
	}}
	if err := manifest.Write(manifestPath); err != nil {
		t.Fatal(err)
	}
	findings := []scanner.Finding{
		{Host: "host", Share: "share", FilePath: "root/positive.txt", RuleID: "one", Category: "credentials", Severity: "high", Confidence: "high", TriageClass: "actionable", Actionable: true, SignalType: "content"},
		{Host: "host", Share: "share", FilePath: "root/positive.txt", RuleID: "two", Category: "credentials", Severity: "medium", Confidence: "medium", TriageClass: "actionable", Actionable: true, SignalType: "content"},
		{Host: "host", Share: "share", FilePath: "root/unexpected.txt", RuleID: "unexpected", Category: "credentials", Severity: "low"},
	}
	legacy, err := VerifyFindings(manifestPath, findings)
	if err != nil {
		t.Fatal(err)
	}
	streamed, err := VerifyFindingIteratorSummary(manifestPath, func(visit func(scanner.Finding) error) error {
		for _, finding := range findings {
			if err := visit(finding); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if streamed.ExpectedItems != legacy.ExpectedItems || streamed.FoundItems != legacy.FoundItems || streamed.MissedItems != legacy.MissedItems || streamed.UnexpectedFindings != legacy.UnexpectedFindings {
		t.Fatalf("streamed summary differs: legacy=%+v streamed=%+v", legacy, streamed)
	}
	if len(streamed.ClassCoverage) != len(legacy.ClassCoverage) || streamed.ClassCoverage[0] != legacy.ClassCoverage[0] {
		t.Fatalf("streamed class coverage differs: legacy=%+v streamed=%+v", legacy.ClassCoverage, streamed.ClassCoverage)
	}
}

func TestVerifyFindingIteratorPropagatesCancellationError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := (Manifest{Entries: []SeedManifestEntry{{Host: "host", Share: "share", Path: "item.txt", Category: "x", ExpectedClass: seedClassCredential}}}).Write(manifestPath); err != nil {
		t.Fatal(err)
	}
	want := os.ErrClosed
	_, err := VerifyFindingIteratorSummary(manifestPath, func(visit func(scanner.Finding) error) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("iterator error=%v, want %v", err, want)
	}
}

func BenchmarkVerifyFindingIteratorSummary(b *testing.B) {
	for _, size := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("findings-%d", size), func(b *testing.B) {
			dir := b.TempDir()
			manifestPath := filepath.Join(dir, "manifest.json")
			manifest := Manifest{Entries: []SeedManifestEntry{{Host: "host", Share: "share", Path: "root/positive.txt", Category: "credentials", ExpectedClass: seedClassCredential}}}
			if err := manifest.Write(manifestPath); err != nil {
				b.Fatal(err)
			}
			findings := make([]scanner.Finding, size)
			for i := range findings {
				findings[i] = scanner.Finding{Host: "host", Share: "share", FilePath: "root/positive.txt", RuleID: fmt.Sprintf("rule-%d", i), Category: "credentials", Severity: "medium", Confidence: "medium", TriageClass: "actionable", Actionable: true, SignalType: "content"}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := VerifyFindingIteratorSummary(manifestPath, func(visit func(scanner.Finding) error) error {
					for _, finding := range findings {
						if err := visit(finding); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

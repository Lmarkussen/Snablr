package diff

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/scanner"
)

func TestCompareCategorizesFindings(t *testing.T) {
	t.Parallel()

	previous := []scanner.Finding{
		{
			RuleID:   "rule.same",
			RuleName: "Same",
			Severity: "high",
			Category: "credentials",
			Host:     "fileserver01",
			Share:    "finance",
			FilePath: "config/app.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.changed",
			RuleName: "Changed",
			Severity: "medium",
			Category: "credentials",
			Host:     "fileserver01",
			Share:    "finance",
			FilePath: "config/db.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.removed",
			RuleName: "Removed",
			Severity: "low",
			Category: "configuration",
			Host:     "fileserver01",
			Share:    "finance",
			FilePath: "config/old.conf",
			Match:    "legacy",
		},
	}

	current := []scanner.Finding{
		previous[0],
		{
			RuleID:   "rule.changed",
			RuleName: "Changed",
			Severity: "high",
			Category: "credentials",
			Host:     "fileserver01",
			Share:    "finance",
			FilePath: "config/db.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.new",
			RuleName: "New",
			Severity: "critical",
			Category: "credentials",
			Host:     "fs02",
			Share:    "hr",
			FilePath: "Policies/Groups.xml",
			Match:    "cpassword",
		},
	}

	result := Compare(previous, current)
	summary := result.Summary()

	if summary.New != 1 || summary.Removed != 1 || summary.Changed != 1 || summary.Unchanged != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if len(result.Changed[0].ChangedFields) == 0 || result.Changed[0].ChangedFields[0] != "severity" {
		t.Fatalf("expected severity change, got %#v", result.Changed[0])
	}
}

func TestFingerprintNormalizesIdentity(t *testing.T) {
	t.Parallel()

	left := Fingerprint(scanner.Finding{
		RuleID:   "RULE.ID",
		Host:     "FILESERVER01",
		Share:    "Finance",
		FilePath: `Config\App.conf`,
		Match:    "Password = Placeholder",
	})
	right := Fingerprint(scanner.Finding{
		RuleID:   "rule.id",
		Host:     "fileserver01",
		Share:    "finance",
		FilePath: "config/app.conf",
		Match:    "password = placeholder",
	})

	if left != right {
		t.Fatalf("expected normalized fingerprints to match: %#v != %#v", left, right)
	}
}

func TestStreamJSONFindingsIncrementallyConvertsAndCancels(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "baseline.json")
	content := `{"summary":{},"findings":[{"rule_id":"r1","rule_name":"R1","severity":"high","category":"credentials","file_path":"a.txt","match":"one"},{"rule_id":"r2","rule_name":"R2","severity":"low","category":"credentials","file_path":"b.txt","match":"two"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var findings []scanner.Finding
	if err := StreamJSONFindings(context.Background(), path, func(finding scanner.Finding) error {
		findings = append(findings, finding)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[1].Match != "two" {
		t.Fatalf("unexpected streamed findings: %#v", findings)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := StreamJSONFindings(ctx, path, func(scanner.Finding) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

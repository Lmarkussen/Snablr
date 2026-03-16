package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/benchmark"
)

func TestRun(t *testing.T) {
	t.Parallel()

	dataset := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataset, "alice-creds.txt"), []byte("NOT_A_REAL_SECRET"), 0o600); err != nil {
		t.Fatalf("write dataset file: %v", err)
	}

	rulesDir := t.TempDir()
	ruleYAML := `version: 1
name: test-rules
rules:
  - id: filename.test_creds
    name: Test Cred Filename
    description: Detect synthetic credential filenames.
    type: filename
    pattern: '(?i)creds'
    case_sensitive: false
    severity: high
    confidence: medium
    tags: [test]
    category: credentials
    enabled: true
    include_paths: []
    exclude_paths: []
    file_extensions: [.txt]
    max_file_size: 0
    action: report
`
	if err := os.WriteFile(filepath.Join(rulesDir, "rules.yml"), []byte(ruleYAML), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	labelsPath := filepath.Join(t.TempDir(), "labels.yml")
	labelsYAML := `version: 1
name: eval-test
expectations:
  - id: expected-creds
    path: alice-creds.txt
    category: credentials
    rule_ids: [filename.test_creds]
    minimum_severity: high
    minimum_confidence: low
`
	if err := os.WriteFile(labelsPath, []byte(labelsYAML), 0o600); err != nil {
		t.Fatalf("write labels file: %v", err)
	}

	report, err := Run(context.Background(), benchmark.Config{
		Dataset:        dataset,
		RulesDirectory: rulesDir,
		LogLevel:       "error",
	}, labelsPath)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if report.Summary.MatchedTotal != 1 {
		t.Fatalf("expected 1 matched finding, got %d", report.Summary.MatchedTotal)
	}
	if report.Summary.MissedTotal != 0 {
		t.Fatalf("expected 0 misses, got %d", report.Summary.MissedTotal)
	}
	if report.Summary.NoisyTotal != 0 {
		t.Fatalf("expected 0 noisy findings, got %d", report.Summary.NoisyTotal)
	}
}

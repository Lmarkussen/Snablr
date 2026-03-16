package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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

	report, err := Run(context.Background(), Config{
		Dataset:        dataset,
		RulesDirectory: rulesDir,
		LogLevel:       "error",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if report.GroupedFindings != 1 {
		t.Fatalf("expected 1 grouped finding, got %d", report.GroupedFindings)
	}
	if got := report.Metrics.Counters.FilesVisited; got != 1 {
		t.Fatalf("expected 1 visited file, got %d", got)
	}
}

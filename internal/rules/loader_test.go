package rules

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRuleFilesLoadsYAMLAndWarnsOnUnsupportedFields(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "rules", "unit")
	files, issues, err := LoadRuleFiles([]string{root})
	if err != nil {
		t.Fatalf("LoadRuleFiles returned error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 rule files, got %d", len(files))
	}

	foundUnsupported := false
	for _, issue := range issues {
		if strings.Contains(issue.Message, "unsupported field") {
			foundUnsupported = true
			break
		}
	}
	if !foundUnsupported {
		t.Fatalf("expected unsupported field issue, got %#v", issues)
	}
}

func TestLoadRuleFilesSupportsExplainabilityFields(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "rules", "unit")
	files, _, err := LoadRuleFiles([]string{root})
	if err != nil {
		t.Fatalf("LoadRuleFiles returned error: %v", err)
	}

	var found Rule
	for _, file := range files {
		for _, rule := range file.Rules {
			if rule.ID == "content.synthetic_password" {
				found = rule
				break
			}
		}
	}

	if found.ID == "" {
		t.Fatal("expected to load content.synthetic_password")
	}
	if found.Confidence != ConfidenceMedium {
		t.Fatalf("expected confidence %q, got %q", ConfidenceMedium, found.Confidence)
	}
	if found.Explanation == "" || found.Remediation == "" {
		t.Fatalf("expected explanation and remediation to load, got %#v", found)
	}
}

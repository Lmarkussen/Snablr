package rules

import (
	"path/filepath"
	"testing"
)

func TestManagerMatchesAndExcludes(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "rules", "unit")
	manager, issues, err := LoadManager([]string{root}, false, ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	if len(issues) == 0 {
		t.Fatalf("expected validation warning from unsupported field fixture")
	}

	filenameMatches := manager.MatchFilename(Candidate{
		Path:      "configs/app.env",
		Name:      "app.env",
		Extension: ".env",
	})
	if len(filenameMatches) != 1 || filenameMatches[0].Rule.ID != "filename.synthetic_env" {
		t.Fatalf("unexpected filename matches: %#v", filenameMatches)
	}

	contentMatches := manager.MatchContent(Candidate{
		Path:      "configs/sample.conf",
		Name:      "sample.conf",
		Extension: ".conf",
		Content:   "password = ReplaceMe123!",
		Size:      64,
	})
	if len(contentMatches) != 1 || contentMatches[0].Rule.ID != "content.synthetic_password" {
		t.Fatalf("unexpected content matches: %#v", contentMatches)
	}
	if contentMatches[0].Rule.Confidence != ConfidenceMedium {
		t.Fatalf("expected rule confidence to be preserved, got %#v", contentMatches[0].Rule.Confidence)
	}
	if contentMatches[0].Rule.Explanation == "" || contentMatches[0].Rule.Remediation == "" {
		t.Fatalf("expected rule explainability metadata, got %#v", contentMatches[0].Rule)
	}

	skip, rule := manager.ShouldExclude(Candidate{
		Path:      "vendor/app.env",
		Name:      "app.env",
		Extension: ".env",
	})
	if !skip || rule == nil || rule.ID != "skip.synthetic_vendor" {
		t.Fatalf("expected vendor path to be excluded, got skip=%v rule=%#v", skip, rule)
	}
}

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

func TestDefaultRulesMatchExactSecretStoreArtifacts(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, issues, err := LoadManager([]string{root}, false, ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected default rules to validate cleanly, got %#v", issues)
	}

	matches := manager.MatchFilename(Candidate{
		Path:      "Dump/NTDS.DIT",
		Name:      "NTDS.DIT",
		Extension: "",
		Size:      4096,
	})
	if len(matches) == 0 {
		t.Fatal("expected NTDS.DIT to match default secret-store rule")
	}
	if matches[0].Rule.ID != "filename.secret_store_artifacts" {
		t.Fatalf("unexpected rule match: %#v", matches)
	}

	nearMiss := manager.MatchFilename(Candidate{
		Path:      "Docs/shadow-notes.txt",
		Name:      "shadow-notes.txt",
		Extension: ".txt",
		Size:      128,
	})
	for _, match := range nearMiss {
		if match.Rule.ID == "filename.secret_store_artifacts" {
			t.Fatalf("did not expect near-miss filename to match secret-store rule: %#v", nearMiss)
		}
	}

	windowsHiveMatches := manager.MatchFilename(Candidate{
		Path:      "Windows/System32/config/SYSTEM",
		Name:      "SYSTEM",
		Extension: "",
		Size:      8192,
	})
	if len(windowsHiveMatches) == 0 {
		t.Fatal("expected SYSTEM hive in Windows config path to match default hive rule")
	}
	if windowsHiveMatches[0].Rule.ID != "filename.windows_hive_artifacts" {
		t.Fatalf("unexpected Windows hive match: %#v", windowsHiveMatches)
	}

	hiveNearMiss := manager.MatchFilename(Candidate{
		Path:      "Docs/system.txt",
		Name:      "system.txt",
		Extension: ".txt",
		Size:      64,
	})
	for _, match := range hiveNearMiss {
		if match.Rule.ID == "filename.windows_hive_artifacts" {
			t.Fatalf("did not expect ordinary system.txt to match Windows hive rule: %#v", hiveNearMiss)
		}
	}

	adBackupMatches := manager.MatchFilename(Candidate{
		Path:      "Dump/NTDS.DIT.bak",
		Name:      "NTDS.DIT.bak",
		Extension: ".bak",
		Size:      8192,
	})
	if len(adBackupMatches) == 0 || adBackupMatches[0].Rule.ID != "filename.ad_database_backup_artifacts" {
		t.Fatalf("expected NTDS.DIT.bak to match AD database backup rule, got %#v", adBackupMatches)
	}

	hiveBackupMatches := manager.MatchFilename(Candidate{
		Path:      "Windows/System32/config/SYSTEM.bak",
		Name:      "SYSTEM.bak",
		Extension: ".bak",
		Size:      8192,
	})
	if len(hiveBackupMatches) == 0 || hiveBackupMatches[0].Rule.ID != "filename.windows_hive_backup_artifacts" {
		t.Fatalf("expected SYSTEM.bak in Windows config path to match hive backup rule, got %#v", hiveBackupMatches)
	}

	hiveBackupNearMiss := manager.MatchFilename(Candidate{
		Path:      "Docs/system.bak",
		Name:      "system.bak",
		Extension: ".bak",
		Size:      64,
	})
	for _, match := range hiveBackupNearMiss {
		if match.Rule.ID == "filename.windows_hive_backup_artifacts" {
			t.Fatalf("did not expect generic system.bak to match hive backup rule: %#v", hiveBackupNearMiss)
		}
	}
}

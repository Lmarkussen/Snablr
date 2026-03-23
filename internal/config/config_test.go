package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFindsConfigFromBinWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "app:\n  name: snablr\n")
	mkdirAll(t, filepath.Join(root, "configs", "rules", "default"))
	mkdirAll(t, filepath.Join(root, "configs", "rules", "custom"))
	mkdirAll(t, filepath.Join(root, "bin"))

	restore := chdir(t, filepath.Join(root, "bin"))
	defer restore()

	cfg, err := Load("configs/config.yaml")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	rulePaths := cfg.RulePaths()
	if len(rulePaths) != 2 {
		t.Fatalf("expected 2 default rule paths, got %d", len(rulePaths))
	}
	if got := rulePaths[0]; got != filepath.Join(root, "configs", "rules", "default") {
		t.Fatalf("unexpected default rule path: %s", got)
	}
	if got := rulePaths[1]; got != filepath.Join(root, "configs", "rules", "custom") {
		t.Fatalf("unexpected custom rule path: %s", got)
	}
}

func TestRulePathsPreferConfigRelativeRuleDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "rules:\n  rules_directory: ../custom-rules\n")
	mkdirAll(t, filepath.Join(root, "custom-rules"))

	cfg, err := Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	rulePaths := cfg.RulePaths()
	if len(rulePaths) != 1 {
		t.Fatalf("expected 1 rule path, got %d", len(rulePaths))
	}
	if got := rulePaths[0]; got != filepath.Join(root, "custom-rules") {
		t.Fatalf("unexpected config-relative rule path: %s", got)
	}
}

func TestRulePathsFallbackToRuntimeRootForCLIStyleRelativeOverride(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "app:\n  name: snablr\n")
	mkdirAll(t, filepath.Join(root, "configs", "rules", "default"))

	cfg, err := Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	cfg.Rules.Directory = filepath.Join("configs", "rules", "default")
	rulePaths := cfg.RulePaths()
	if len(rulePaths) != 1 {
		t.Fatalf("expected 1 rule path, got %d", len(rulePaths))
	}
	if got := rulePaths[0]; got != filepath.Join(root, "configs", "rules", "default") {
		t.Fatalf("unexpected runtime-root rule path: %s", got)
	}
}

func TestLoadAppliesArchiveDefaultsAndHonorsExplicitDisable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "archives:\n  enabled: false\n")

	cfg, err := Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Archives.Enabled {
		t.Fatalf("expected explicit archive disable to be preserved, got %#v", cfg.Archives)
	}
	if cfg.Archives.AutoZIPMaxSize != 10*1024*1024 || cfg.Archives.MaxMembers != 64 || cfg.Archives.MaxMemberBytes == 0 || cfg.Archives.MaxTotalUncompressed == 0 {
		t.Fatalf("expected archive defaults to be applied, got %#v", cfg.Archives)
	}
}

func TestLoadAppliesProfileBeforeExplicitOverrides(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "scan:\n  profile: validation\narchives:\n  max_members: 99\n")

	cfg, err := Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Scan.Profile != "validation" {
		t.Fatalf("expected validation profile, got %#v", cfg.Scan.Profile)
	}
	if !cfg.Scan.ValidationMode {
		t.Fatalf("expected validation profile to enable validation mode, got %#v", cfg.Scan)
	}
	if cfg.Archives.MaxMembers != 99 {
		t.Fatalf("expected explicit config override to win after profile application, got %#v", cfg.Archives)
	}
}

func TestLoadMergesSuppressionOverlay(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "configs", "config.yaml"), "suppression:\n  file: suppressions.yaml\n  rules:\n    - id: inline-rule\n      reason: inline\n      enabled: true\n      exact_paths: [Users/Alice/Desktop/passwords.txt]\n")
	writeFile(t, filepath.Join(root, "configs", "suppressions.yaml"), "sample_limit: 3\nrules:\n  - id: overlay-rule\n    reason: overlay\n    enabled: true\n    rule_ids: [content.synthetic_password]\n")

	cfg, err := Load(filepath.Join(root, "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Suppression.SampleLimit != 3 {
		t.Fatalf("expected suppression overlay sample limit, got %#v", cfg.Suppression)
	}
	if len(cfg.Suppression.Rules) != 2 {
		t.Fatalf("expected inline and overlay suppression rules, got %#v", cfg.Suppression.Rules)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	mkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) returned error: %v", path, err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) returned error: %v", path, err)
	}
}

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s) returned error: %v", dir, err)
	}
	return func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore Chdir(%s) returned error: %v", wd, err)
		}
	}
}

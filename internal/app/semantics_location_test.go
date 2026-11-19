package app

import (
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/config"
	"snablr/internal/rules"
)

// The same rules loaded from two different directories, such as two
// checkouts of the same version, describe the same scan semantics.
func TestScanSemanticsDoNotDependOnRulesLocation(t *testing.T) {
	source := filepath.Join("..", "..", "configs", "rules", "default")
	load := func() *rules.Manager {
		dir := filepath.Join(t.TempDir(), "rules")
		if err := os.CopyFS(dir, os.DirFS(source)); err != nil {
			t.Fatal(err)
		}
		manager, _, err := rules.LoadManager([]string{dir}, false, rules.ManagerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}
	cfg := config.Default()
	first, second := scanSemanticsFingerprint(cfg, load()), scanSemanticsFingerprint(cfg, load())
	if first != second {
		t.Fatal("the same rules in another directory give different scan semantics")
	}
}

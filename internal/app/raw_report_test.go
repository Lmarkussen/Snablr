package app

import (
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/config"
)

func TestRawHTMLReportPathUsesSafeCollisionSuffixes(t *testing.T) {
	workspace := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	cfg := config.Config{Scan: config.ScanConfig{Domain: "SCCM.LAB"}}
	if err := os.WriteFile("SCCM_LAB_RAW.html", []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := rawHTMLReportPath(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(workspace, "SCCM_LAB_2_RAW.html")
	if path != want {
		t.Fatalf("RAW path = %q, want %q", path, want)
	}
}

func TestRawHTMLReportPathUsesExplicitTargetForSingleTarget(t *testing.T) {
	cfg := config.Config{Scan: config.ScanConfig{Targets: []string{"10.1.10.41"}, Domain: "SCCM.LAB"}}
	path, err := rawHTMLReportPath(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "10_1_10_41_RAW.html" {
		t.Fatalf("RAW path = %q", path)
	}
}

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/ui"
)

func captureCLIStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	fn()
	_ = writer.Close()
	os.Stdout = original
	output, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

func TestScanHelpSeparatesCommonAndAdvancedFlags(t *testing.T) {
	normal := captureCLIStdout(t, func() { _ = runScan([]string{"--help"}) })
	advanced := captureCLIStdout(t, func() { _ = runScan([]string{"--help-advanced"}) })
	for _, flag := range []string{"--targets", "--share", "--resume", "--force-rescan", "--dbname", "--flushdb", "--list-shares", "--no-color"} {
		if !strings.Contains(normal, flag) {
			t.Fatalf("normal scan help missing %s", flag)
		}
	}
	for _, flag := range []string{"--nt-hash", "--kerberos-ccache", "--validation-mode", "--wim-max-images", "--report-backup-artifacts"} {
		if !strings.Contains(advanced, flag) {
			t.Fatalf("advanced scan help missing %s", flag)
		}
	}
	if strings.Contains(normal, "--wim-max-images") {
		t.Fatal("normal scan help exposes specialized WIM flags")
	}
}

func TestDeveloperHelpAndDispatch(t *testing.T) {
	help := captureCLIStdout(t, func() { _ = runDev([]string{"--help"}) })
	for _, command := range []string{"benchmark", "eval", "rules"} {
		if !strings.Contains(help, command) {
			t.Fatalf("developer help missing %s", command)
		}
	}
	if err := runDev([]string{"unknown"}); err == nil {
		t.Fatal("unknown developer command unexpectedly succeeded")
	}
}

func TestFindHelpIncludesDatabaseAlias(t *testing.T) {
	help := captureCLIStdout(t, func() { _ = runFind([]string{"--help"}) })
	for _, flag := range []string{"--db", "--dbname"} {
		if !strings.Contains(help, flag) {
			t.Fatalf("find help missing %s", flag)
		}
	}
}

func TestFindDatabaseAliasRejectsConflictsWithoutOpeningEitherPath(t *testing.T) {
	left := filepath.Join(t.TempDir(), "left.db")
	right := filepath.Join(t.TempDir(), "right.db")
	if err := runFind([]string{"--db", left, "--dbname", right}); err == nil {
		t.Fatal("expected conflicting Finder database flags to be rejected")
	}
	if got, err := reconcileFinderDatabasePaths(left, left); err != nil || got != left {
		t.Fatalf("same Finder database flags = %q, %v", got, err)
	}
	for _, flag := range []string{"--db", "--dbname"} {
		path := filepath.Join(t.TempDir(), flag[2:]+".db")
		if err := runFind([]string{flag, path}); err == nil {
			t.Fatalf("expected missing explicit Finder database to fail for %s", flag)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("Finder %s created or modified missing database: %v", flag, err)
		}
	}
}

func TestHelpOutputWrapsAtConfiguredWidth(t *testing.T) {
	oldColumns := os.Getenv("COLUMNS")
	if err := os.Setenv("COLUMNS", "40"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if oldColumns == "" {
			_ = os.Unsetenv("COLUMNS")
		} else {
			_ = os.Setenv("COLUMNS", oldColumns)
		}
	}()
	output := captureCLIStdout(t, func() { _ = runScan([]string{"--help"}) })
	for _, line := range strings.Split(output, "\n") {
		if len([]rune(line)) > 40 {
			t.Fatalf("help line exceeds configured width: %d %q", len([]rune(line)), line)
		}
	}
}

func TestBannerPlainModeNeverEmitsANSI(t *testing.T) {
	var output bytes.Buffer
	ui.PrintBannerWithColor(&output, false)
	if strings.Contains(output.String(), "\033[") {
		t.Fatal("plain banner emitted ANSI escape sequences")
	}
}

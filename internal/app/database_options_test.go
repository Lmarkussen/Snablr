package app

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/store"
)

func TestPrepareScanDatabaseFlushesOnlyValidatedSnablrDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assessment.db")
	state, err := store.Open(path, store.Options{ScanID: "old-scan", ScanDomain: "old.local", Semantics: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RecordTarget("old-host", "completed", storeTestTimeForDatabaseOptions()); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepareScanDatabase(config.Config{}, ScanOptions{FlushDatabase: path}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var scans, targets int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&scans); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if scans != 0 || targets != 0 {
		t.Fatalf("flush left scans=%d targets=%d", scans, targets)
	}
}

func TestPrepareScanDatabaseRejectsFlushFailuresBeforeScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-snablr.db")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareScanDatabase(config.Config{}, ScanOptions{FlushDatabase: path}); err == nil {
		t.Fatal("expected invalid flush target to abort")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("invalid flush target was modified")
	}
}

func TestPrepareScanDatabaseRejectsProtectedAndAmbiguousTargets(t *testing.T) {
	protected := filepath.Join(t.TempDir(), "internal", "app", "snablr.db")
	if err := os.MkdirAll(filepath.Dir(protected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareScanDatabase(config.Config{}, ScanOptions{FlushDatabase: protected}); err == nil {
		t.Fatal("expected protected database rejection")
	}
	one := filepath.Join(t.TempDir(), "one.db")
	two := filepath.Join(t.TempDir(), "two.db")
	if err := prepareScanDatabase(config.Config{}, ScanOptions{DatabaseName: one, FlushDatabase: two}); err == nil {
		t.Fatal("expected mismatched database options rejection")
	}
}

func TestScanDatabaseResolutionKeepsDefaultAndExplicitPaths(t *testing.T) {
	if got := sqliteStatePath(config.Config{}); got != "snablr.db" {
		t.Fatalf("default database path=%q, want snablr.db", got)
	}
	defaultConfig := config.Config{}
	applyScanOverrides(&defaultConfig, ScanOptions{})
	if got := sqliteStatePath(defaultConfig); got != "snablr.db" {
		t.Fatalf("default override path=%q, want snablr.db", got)
	}
	explicitConfig := config.Config{}
	applyScanOverrides(&explicitConfig, ScanOptions{DatabaseName: "customer.db"})
	if got := sqliteStatePath(explicitConfig); got != "customer.db" {
		t.Fatalf("explicit database path=%q, want customer.db", got)
	}
}

func storeTestTimeForDatabaseOptions() (result time.Time) {
	return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
}

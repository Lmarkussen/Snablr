package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreSaveAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	store, err := Open(path, false)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	store.MarkHostComplete("FS01")
	store.MarkShareComplete("FS01", "Finance")
	modifiedAt := time.Date(2026, 3, 17, 15, 0, 0, 0, time.UTC)
	store.MarkFileComplete("FS01", "Finance", "reports/payroll.csv", 4096, modifiedAt)
	if err := store.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open resume returned error: %v", err)
	}

	if !resumed.IsHostComplete("fs01") {
		t.Fatalf("expected host completion to round-trip")
	}
	if !resumed.IsShareComplete("fs01", "finance") {
		t.Fatalf("expected share completion to round-trip")
	}
	if !resumed.IsFileComplete("fs01", "finance", "reports/payroll.csv", 4096, modifiedAt) {
		t.Fatalf("expected file completion to round-trip")
	}
}

func TestManagerMarksShareCompleteOnlyWhenAllFilesSucceed(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	manager, err := NewManager(path, false, 0)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	manager.BeginShare("FS01", "Finance", 2)
	modifiedAt := time.Date(2026, 3, 17, 15, 5, 0, 0, time.UTC)
	manager.RecordFileResult("FS01", "Finance", "one.txt", 10, modifiedAt, true)
	manager.RecordFileResult("FS01", "Finance", "two.txt", 20, modifiedAt, false)
	manager.MarkHostComplete("FS01")
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if resumed.IsShareComplete("fs01", "finance") {
		t.Fatalf("did not expect share completion after failed file")
	}
	if !resumed.IsFileComplete("fs01", "finance", "one.txt", 10, modifiedAt) {
		t.Fatalf("expected successful file to be saved")
	}
	if resumed.IsFileComplete("fs01", "finance", "two.txt", 20, modifiedAt) {
		t.Fatalf("did not expect failed file to be saved")
	}
}

func TestManagerSupportsIncrementalShareEnumeration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	manager, err := NewManager(path, false, 0)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	manager.StartShare("FS01", "Finance")
	manager.AddPendingFiles("FS01", "Finance", 2)
	modifiedAt := time.Date(2026, 3, 17, 15, 10, 0, 0, time.UTC)
	manager.RecordFileResult("FS01", "Finance", "one.txt", 10, modifiedAt, true)
	manager.FinishShareEnumeration("FS01", "Finance")
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if resumed.IsShareComplete("fs01", "finance") {
		t.Fatal("did not expect share completion while one file is still pending")
	}

	manager.RecordFileResult("FS01", "Finance", "two.txt", 20, modifiedAt, true)
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err = Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !resumed.IsShareComplete("fs01", "finance") {
		t.Fatal("expected share completion after enumeration finished and all files succeeded")
	}
}

func TestStoreReprocessesFilesWhenSizeOrTimestampChanges(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	store, err := Open(path, false)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	modifiedAt := time.Date(2026, 3, 17, 15, 15, 0, 0, time.UTC)
	store.MarkFileComplete("FS01", "Finance", "reports/payroll.csv", 4096, modifiedAt)
	if err := store.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open resume returned error: %v", err)
	}

	if resumed.IsFileComplete("fs01", "finance", "reports/payroll.csv", 8192, modifiedAt) {
		t.Fatal("expected size change to invalidate checkpoint entry")
	}
	if resumed.IsFileComplete("fs01", "finance", "reports/payroll.csv", 4096, modifiedAt.Add(time.Minute)) {
		t.Fatal("expected timestamp change to invalidate checkpoint entry")
	}
}

func TestStoreSupportsLegacyPathOnlyCheckpoints(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	data := []byte("{\n  \"version\": 1,\n  \"completed_files\": [\"fs01::finance::reports/payroll.csv\"]\n}\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy checkpoint: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open resume returned error: %v", err)
	}
	if !resumed.IsFileComplete("fs01", "finance", "reports/payroll.csv", 4096, time.Date(2026, 3, 17, 15, 20, 0, 0, time.UTC)) {
		t.Fatal("expected legacy path-only checkpoint to remain resumable")
	}
}

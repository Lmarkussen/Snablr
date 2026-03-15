package state

import (
	"path/filepath"
	"testing"
)

func TestStoreSaveAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	store, err := Open(path, false)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}

	store.MarkHostComplete("FILESERVER01")
	store.MarkShareComplete("FILESERVER01", "Finance")
	store.MarkFileComplete("FILESERVER01", "Finance", "reports/payroll.csv")
	if err := store.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open resume returned error: %v", err)
	}

	if !resumed.IsHostComplete("fileserver01") {
		t.Fatalf("expected host completion to round-trip")
	}
	if !resumed.IsShareComplete("fileserver01", "finance") {
		t.Fatalf("expected share completion to round-trip")
	}
	if !resumed.IsFileComplete("fileserver01", "finance", "reports/payroll.csv") {
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

	manager.BeginShare("FILESERVER01", "Finance", 2)
	manager.RecordFileResult("FILESERVER01", "Finance", "one.txt", true)
	manager.RecordFileResult("FILESERVER01", "Finance", "two.txt", false)
	manager.MarkHostComplete("FILESERVER01")
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if resumed.IsShareComplete("fileserver01", "finance") {
		t.Fatalf("did not expect share completion after failed file")
	}
	if !resumed.IsFileComplete("fileserver01", "finance", "one.txt") {
		t.Fatalf("expected successful file to be saved")
	}
	if resumed.IsFileComplete("fileserver01", "finance", "two.txt") {
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

	manager.StartShare("FILESERVER01", "Finance")
	manager.AddPendingFiles("FILESERVER01", "Finance", 2)
	manager.RecordFileResult("FILESERVER01", "Finance", "one.txt", true)
	manager.FinishShareEnumeration("FILESERVER01", "Finance")
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err := Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if resumed.IsShareComplete("fileserver01", "finance") {
		t.Fatal("did not expect share completion while one file is still pending")
	}

	manager.RecordFileResult("FILESERVER01", "Finance", "two.txt", true)
	if err := manager.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	resumed, err = Open(path, true)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !resumed.IsShareComplete("fileserver01", "finance") {
		t.Fatal("expected share completion after enumeration finished and all files succeeded")
	}
}

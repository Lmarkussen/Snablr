package state

import (
	"testing"
	"time"

	"snablr/internal/store"
)

func TestHostCompleteRequiresEveryShareToComplete(t *testing.T) {
	manager := NewManagerFromSQLiteReader(nil, 0)
	manager.StartShare("synthetic-host", "SyntheticShare")
	manager.AddPendingFiles("synthetic-host", "SyntheticShare", 1)
	manager.FinishShareEnumeration("synthetic-host", "SyntheticShare")
	manager.RecordFileResult("synthetic-host", "SyntheticShare", "failed.txt", 1, syntheticTime(), false)
	if manager.HostComplete("synthetic-host", 1) {
		t.Fatal("failed share was treated as a completed host")
	}
}

func TestHostCompleteAcceptsCompletedAndReusedShares(t *testing.T) {
	manager := NewManagerFromSQLiteReader(nil, 0)
	manager.StartShare("synthetic-host", "FreshShare")
	manager.AddPendingFiles("synthetic-host", "FreshShare", 1)
	manager.FinishShareEnumeration("synthetic-host", "FreshShare")
	manager.RecordFileResult("synthetic-host", "FreshShare", "done.txt", 1, syntheticTime(), true)
	if !manager.HostComplete("synthetic-host", 1) {
		t.Fatal("completed share was not treated as a completed host")
	}
}

func syntheticTime() (value time.Time) {
	return time.Unix(0, 0).UTC()
}

func TestScopeSkipPersistsAndDoesNotCompleteShare(t *testing.T) {
	path := t.TempDir() + "/state.db"
	authority, err := store.Open(path, store.Options{ScanID: "scan-synthetic", Semantics: "semantics-synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	manager := NewManagerFromSQLiteReader(nil, 0)
	manager.AttachStore(authority, authority.ScanID())
	manager.StartShare("host", "share")
	manager.AddPendingFiles("host", "share", 1)
	if err := manager.SkipFolder("host", "share", `1\\2\\3`); err != nil {
		t.Fatal(err)
	}
	if manager.ShouldDescend("host", "share", "1/2/30") == false {
		t.Fatal("folder boundary collision excluded sibling")
	}
	if manager.ShouldDescend("host", "share", "1/2/3/Nested") {
		t.Fatal("excluded folder descendant remained eligible")
	}
	manager.FinishShareEnumeration("host", "share")
	manager.RecordFileResult("host", "share", "in-flight.txt", 1, syntheticTime(), true)
	if manager.HostComplete("host", 1) {
		t.Fatal("share with skipped folder was treated as complete")
	}
}

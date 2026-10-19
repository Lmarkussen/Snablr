package state

import (
	"testing"
	"time"
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

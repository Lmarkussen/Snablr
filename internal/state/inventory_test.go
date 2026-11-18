package state

import (
	"testing"
	"time"
)

type inventoryReader struct{}

func (inventoryReader) ResumeTargetComplete(string) (bool, error)        { return false, nil }
func (inventoryReader) ResumeShareComplete(string, string) (bool, error) { return false, nil }
func (inventoryReader) LookupFile(string, string, string) (SQLiteFileState, bool, error) {
	return SQLiteFileState{}, false, nil
}
func (inventoryReader) LookupAccess(string, string) (bool, error) { return false, nil }
func (inventoryReader) IsScopeExcluded(string, string, string, string) (bool, error) {
	return false, nil
}

type inventoryStateSink struct {
	files      int
	lastStatus string
}

func (inventoryStateSink) RecordTarget(string, string, time.Time) error        { return nil }
func (inventoryStateSink) RecordShare(string, string, string, time.Time) error { return nil }
func (inventoryStateSink) RecordScopeExclusion(string, string, string, string, time.Time) error {
	return nil
}
func (s *inventoryStateSink) RecordFile(_, _, _, _, status, _ string, _ int64, _, _, _, _ time.Time) error {
	s.files++
	s.lastStatus = status
	return nil
}
func (inventoryStateSink) RecordAccess(string, string, string, time.Time, time.Time) error {
	return nil
}

func TestSQLiteInventoryReleasesCompletedObjectState(t *testing.T) {
	manager := NewInventoryManagerFromSQLiteReader(inventoryReader{}, time.Second)
	sink := &inventoryStateSink{}
	manager.AttachStore(sink, "scan")
	decision, err := manager.Prepare(FileObservation{Server: "host", Share: "share", Path: "file.txt", Size: 7, ModifiedAt: syntheticTime()}, "ctx", "semantics", false)
	if err != nil {
		t.Fatal(err)
	}
	manager.MarkCompleted(decision.Key)
	if len(manager.inventory.active) != 0 {
		t.Fatalf("completed inventory retained %d active objects", len(manager.inventory.active))
	}
	if sink.files != 2 {
		t.Fatalf("expected prepare and completion persistence, got %d writes", sink.files)
	}
}

// The scan pipeline always marks a file scanning before the worker reports a
// terminal status. The terminal status must still be persisted; previously the
// scanning transition released the object and every file stayed "scanning",
// so --resume could never skip already-inspected files.
func TestSQLiteInventoryPersistsTerminalStatusAfterScanning(t *testing.T) {
	cases := []struct {
		name string
		mark func(*InventoryManager, string)
		want ObjectStatus
	}{
		{name: "completed", mark: (*InventoryManager).MarkCompleted, want: ObjectCompleted},
		{name: "failed", mark: (*InventoryManager).MarkFailed, want: ObjectFailed},
		{name: "partial", mark: (*InventoryManager).MarkPartial, want: ObjectPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewInventoryManagerFromSQLiteReader(inventoryReader{}, time.Second)
			sink := &inventoryStateSink{}
			manager.AttachStore(sink, "scan")
			decision, err := manager.Prepare(FileObservation{Server: "host", Share: "share", Path: "file.txt", Size: 7, ModifiedAt: syntheticTime()}, "ctx", "semantics", false)
			if err != nil {
				t.Fatal(err)
			}
			manager.MarkScanning(decision.Key)
			if sink.lastStatus != string(ObjectScanning) {
				t.Fatalf("scanning transition persisted %q", sink.lastStatus)
			}
			tc.mark(manager, decision.Key)
			if sink.lastStatus != string(tc.want) {
				t.Fatalf("terminal status persisted %q, want %q", sink.lastStatus, tc.want)
			}
			if sink.files != 3 {
				t.Fatalf("expected prepare, scanning and terminal persistence, got %d writes", sink.files)
			}
			if len(manager.inventory.active) != 0 {
				t.Fatalf("terminal inventory retained %d active objects", len(manager.inventory.active))
			}
		})
	}
}

func TestInMemoryProgressDoesNotRetainCompletedFiles(t *testing.T) {
	manager := NewManagerFromSQLiteReader(nil, time.Second)
	manager.RecordFileResultInMemory("host", "share", "file.txt", 7, syntheticTime(), true)
	if got := len(manager.store.files); got != 0 {
		t.Fatalf("in-memory progress retained %d completed file records", got)
	}
}

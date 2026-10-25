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

type inventoryStateSink struct{ files int }

func (inventoryStateSink) RecordTarget(string, string, time.Time) error        { return nil }
func (inventoryStateSink) RecordShare(string, string, string, time.Time) error { return nil }
func (inventoryStateSink) RecordScopeExclusion(string, string, string, string, time.Time) error {
	return nil
}
func (s *inventoryStateSink) RecordFile(string, string, string, string, string, string, int64, time.Time, time.Time, time.Time, time.Time) error {
	s.files++
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

func TestInMemoryProgressDoesNotRetainCompletedFiles(t *testing.T) {
	manager := NewManagerFromSQLiteReader(nil, time.Second)
	manager.RecordFileResultInMemory("host", "share", "file.txt", 7, syntheticTime(), true)
	if got := len(manager.store.files); got != 0 {
		t.Fatalf("in-memory progress retained %d completed file records", got)
	}
}

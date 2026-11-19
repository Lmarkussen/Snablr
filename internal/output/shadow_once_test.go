package output

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

func countPersistedFindings(t *testing.T, shadow *store.SQLiteStore) int {
	t.Helper()
	if err := shadow.Flush(); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := shadow.IterateFindings(context.Background(), 64, func(batch []scanner.Finding) error {
		count += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

// A MultiWriter persists each finding once; previously the MultiWriter and
// every child wrote the same row again (idempotent, but N times the work).
// Children must keep read access to the store for reports and search.
func TestMultiWriterPersistsOnceAndChildrenKeepReadAccess(t *testing.T) {
	shadow, err := store.Open(filepath.Join(t.TempDir(), "once.db"), store.Options{ScanID: "once", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	jsonChild := NewJSONWriter(io.Discard, nil, false)
	consoleChild := NewConsoleWriter(io.Discard, nil)
	multi := &MultiWriter{sinks: []scanner.FindingSink{jsonChild, consoleChild}}
	AttachSQLiteStore(multi, shadow)

	for _, child := range []scanner.FindingSink{jsonChild, consoleChild} {
		if attachedSQLiteStore(child) != shadow {
			t.Fatalf("%T lost read access to the store", child)
		}
		if _, covered := shadowWriteCovered.Load(child); !covered {
			t.Fatalf("%T still writes findings itself", child)
		}
	}
	if _, covered := shadowWriteCovered.Load(multi); covered {
		t.Fatal("MultiWriter must persist findings")
	}
	if err := multi.WriteFinding(scanner.Finding{RuleID: "once.rule", Host: "fs01", Share: "share", FilePath: "a.txt"}); err != nil {
		t.Fatal(err)
	}
	if got := countPersistedFindings(t, shadow); got != 1 {
		t.Fatalf("persisted %d findings, want 1", got)
	}

	alone := NewJSONWriter(io.Discard, nil, false)
	AttachSQLiteStore(alone, shadow)
	if err := alone.WriteFinding(scanner.Finding{RuleID: "alone.rule", Host: "fs01", Share: "share", FilePath: "b.txt"}); err != nil {
		t.Fatal(err)
	}
	if got := countPersistedFindings(t, shadow); got != 2 {
		t.Fatalf("standalone sink did not persist its finding: %d rows", got)
	}
}

package findings

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

func makeFixtureDB(t *testing.T, scanIDs ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snablr.db")
	for i, scanID := range scanIDs {
		state, err := store.Open(path, store.Options{ScanID: scanID, SnablrVersion: "test", Semantics: "synthetic", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		finding := scanner.Finding{RuleID: "synthetic.rule", RuleName: "Synthetic evidence", Severity: "high", Confidence: "high", Actionable: true, Host: "HOST", Share: "Share", FilePath: "evidence.txt", MatchedText: "synthetic-value"}
		if err := state.RecordFinding(finding); err != nil {
			t.Fatal(err)
		}
		if err := state.SetScanStatus(store.StatusCompleted, time.Date(2026, 1, i+1, 12, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if err := state.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestOpenRejectsMissingWithoutCreating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := Open(path); err == nil {
		t.Fatal("expected missing database error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("viewer created or changed missing database: %v", err)
	}
}

func TestProviderListsScansAndFindingsReadOnly(t *testing.T) {
	path := makeFixtureDB(t, "scan-one", "scan-two")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	scans, err := provider.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].FindingCount != 1 {
		t.Fatalf("unexpected scans: %#v", scans)
	}
	items, err := provider.Findings(context.Background(), scans[0].ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != "synthetic-value" {
		t.Fatalf("unexpected findings: %#v", items)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("read-only provider changed the database file")
	}
}

func TestProviderBoundsFindingPage(t *testing.T) {
	path := makeFixtureDB(t, "scan-one")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if _, err := provider.Findings(context.Background(), "scan-one", -1, 1); err == nil {
		t.Fatal("expected negative offset error")
	}
	if _, err := provider.Findings(context.Background(), "scan-one", 0, PageSize+1); err == nil {
		t.Fatal("expected page size error")
	}
}

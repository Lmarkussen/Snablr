package findings

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
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
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticPassword!", Verification: credentialanalysis.Confirmed, Host: "HOST", Share: "Share", Path: "evidence.txt"}); err != nil {
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
	if scans[0].DisplayID != "scan-local-002" || scans[0].ID != "scan-two" {
		t.Fatalf("unexpected scan identifiers: %#v", scans[0])
	}
	items, err := provider.Findings(context.Background(), scans[0].ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != "synthetic-value" {
		t.Fatalf("unexpected findings: %#v", items)
	}
	credentials, err := provider.Credentials(context.Background(), scans[0].ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].Candidate.Value != "SyntheticPassword!" {
		t.Fatalf("unexpected credential projection: %#v", credentials)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("read-only provider changed the database file")
	}
}

func TestProviderFallsBackToLegacyScanIDWhenNoDisplayLabelExists(t *testing.T) {
	path := makeFixtureDB(t, "legacy-scan")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM scan_labels WHERE scan_id=?`, "legacy-scan"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	scans, err := provider.ListScans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].ID != "legacy-scan" || scans[0].DisplayID != "legacy-scan" {
		t.Fatalf("unexpected legacy scan identifiers: %#v", scans)
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

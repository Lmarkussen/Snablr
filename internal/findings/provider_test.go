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

func TestProviderRehydratesDatabaseLocationFindingForFinder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database-location.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-scan", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.Finding{
		RuleID:            "dbinspect.artifact.sqlite_structural",
		RuleName:          "Structurally Validated SQLite Database Artifact",
		Category:          "database-artifacts",
		SignalType:        "validated",
		Confidence:        "medium",
		TriageClass:       "weak-review",
		Host:              "fileserver",
		Share:             "data",
		FilePath:          "exports/opaque-copy",
		MatchedText:       "SQLite format 3\x00",
		Context:           "exports/opaque-copy",
		ArchivePath:       "bundle.zip",
		ArchiveMemberPath: "nested/opaque-copy",
		Tags:              []string{"database", "db:type:sqlite", "db:status:confirmed"},
	}
	if err := state.RecordFinding(want); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	items, err := provider.Findings(context.Background(), "p4-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != want.MatchedText || items[0].Finding.ArchiveMemberPath != want.ArchiveMemberPath {
		t.Fatalf("database finding did not rehydrate exactly: got %#v", items)
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || categories[0].Name != "Database Locations & Connections" {
		t.Fatalf("database finding did not survive Finder projection: %#v", categories)
	}
}

func TestProviderRehydratesStructuredDatabaseConfigurationEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "structured-database.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-config", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.Finding{
		RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Validated Database Configuration Endpoint",
		Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed",
		Host: "fileserver", Share: "configs", FilePath: "opaque-config", MatchedText: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`,
		Snippet: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`, Context: `{"database":{"host":"db.example.test","port":5432,"name":"payroll"}}`,
		Tags: []string{"database", "db:source:config", "db:type:configured-endpoint", "db:status:configured"},
	}
	if err := state.RecordFinding(want); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := provider.Findings(context.Background(), "p4-config", 0, 10)
	if err != nil {
		_ = provider.Close()
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != want.MatchedText || items[0].Finding.Snippet != want.Snippet || items[0].Finding.Context != want.Context {
		t.Fatalf("structured configuration evidence did not rehydrate exactly: got %#v", items)
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "Database Servers & Instances" {
		t.Fatalf("structured configuration did not survive Finder projection: %#v", categories)
	}
}

func TestProviderRehydratesDistinctDatabaseObservationsWithExactEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "distinct-database-observations.db")
	state, err := store.Open(path, store.Options{ScanID: "p4-distinct", SnablrVersion: "test", Semantics: "p4", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	wants := []scanner.Finding{
		{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed", Host: "fileserver", Share: "configs", FilePath: "app.json", MatchedText: "host=prod;database=app", Context: "production", ObservationID: "structured:0:prod"},
		{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", TriageClass: "confirmed", Host: "fileserver", Share: "configs", FilePath: "app.json", MatchedText: "host=report;database=reporting", Context: "reporting", ObservationID: "structured:1:report"},
	}
	for _, want := range wants {
		if err := state.RecordFinding(want); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := provider.Findings(context.Background(), "p4-distinct", 0, 10)
	if err != nil {
		_ = provider.Close()
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if len(items) != len(wants) {
		t.Fatalf("distinct observations were not persisted: got %d items: %#v", len(items), items)
	}
	for index, want := range wants {
		got := items[index].Finding
		if got.ObservationID != want.ObservationID || got.MatchedText != want.MatchedText || got.Context != want.Context {
			t.Fatalf("observation %d changed during persistence: got %#v want %#v", index, got, want)
		}
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 2 {
		t.Fatalf("Finder lost distinct database observations: %#v", categories)
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

func TestProviderPreservesP3CaptureValuesAndTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p3-captures.db")
	values := []credentialanalysis.Candidate{
		{CredentialType: "kerberos_asrep", Identity: "alice", Domain: "SYNTHETIC", Value: "$krb5asrep$23$alice@SYNTHETIC:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "kerberos_tgs", Identity: "alice", Domain: "SYNTHETIC", Value: "$krb5tgs$23$*alice$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "dcc", Identity: "alice", Value: "$DCC1#alice#00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "captures"},
		{CredentialType: "dcc2", Identity: "alice", Value: "$DCC2$10240#alice#00112233445566778899aabbccddeeff", Verification: credentialanalysis.Confirmed, Path: "archive.zip!captures"},
	}
	state, err := store.Open(path, store.Options{ScanID: "p3-scan", SnablrVersion: "test", Semantics: "p3", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range values {
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	got, err := provider.Credentials(context.Background(), "p3-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(values) {
		t.Fatalf("credential count = %d, want %d", len(got), len(values))
	}
	for index, expected := range values {
		if got[index].Candidate.CredentialType != expected.CredentialType || got[index].Candidate.Value != expected.Value || got[index].Candidate.Path != expected.Path {
			t.Fatalf("credential %d = %#v, want %#v", index, got[index].Candidate, expected)
		}
	}
}

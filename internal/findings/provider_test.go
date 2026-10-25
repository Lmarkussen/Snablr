package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

func TestCredentialByIDRestoresAuthoritativeValue(t *testing.T) {
	path := makeFixtureDB(t, "credential-by-id")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	credentials, err := provider.Credentials(context.Background(), "credential-by-id", 0, 10)
	if err != nil || len(credentials) != 1 {
		t.Fatalf("credentials = %#v, err = %v", credentials, err)
	}
	id := credentials[0].ID
	credential, err := provider.CredentialByID(context.Background(), "credential-by-id", id)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Candidate.Identity != "synthetic-user" || credential.Candidate.Value != "SyntheticPassword!" {
		t.Fatalf("credential by id lost recovered values: %#v", credential.Candidate)
	}
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

func TestProviderIncludesCompletedDerivedFindingsWithStableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derived.db")
	state, err := store.Open(path, store.Options{ScanID: "derived-scan", SnablrVersion: "test", Semantics: "test", BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	original := scanner.Finding{RuleID: "original.rule", FilePath: "original.txt", MatchedText: "original"}
	derived := scanner.Finding{RuleID: "correlation.rule", FilePath: "derived.txt", MatchedText: "derived"}
	if err := state.RecordFinding(original); err != nil {
		t.Fatal(err)
	}
	if err := state.ResetCorrelationState(); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordDerivedFinding("family/group", derived); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.CompleteCorrelationState(); err != nil {
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
	counts, err := provider.Counts(context.Background(), "derived-scan")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 2 {
		t.Fatalf("finding count=%d, want 2", counts.Findings)
	}
	page, err := provider.FindingsAfter(context.Background(), "derived-scan", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].Derived {
		t.Fatalf("unexpected original page: %#v", page)
	}
	next, err := provider.FindingsAfter(context.Background(), "derived-scan", page[0].ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || !next[0].Derived || next[0].Finding.RuleID != derived.RuleID {
		t.Fatalf("unexpected derived page: %#v", next)
	}
	if next[0].ID == page[0].ID || next[0].StableID() == fmt.Sprintf("finding:%d", next[0].ID) {
		t.Fatalf("derived identity collided: %#v", next[0])
	}
	rehydrated, err := provider.Finding(context.Background(), "derived-scan", next[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if rehydrated.Finding.MatchedText != derived.MatchedText || !rehydrated.Derived {
		t.Fatalf("rehydrated derived finding: %#v", rehydrated)
	}
	search, err := provider.SearchPage(context.Background(), "derived-scan", "correlation.rule", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(search.Findings) != 1 || !search.Findings[0].Derived {
		t.Fatalf("derived search result: %#v", search.Findings)
	}
}

func TestProviderHidesDerivedFindingsDuringRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "building.db")
	state, err := store.Open(path, store.Options{ScanID: "building-scan", SnablrVersion: "test", Semantics: "test", BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ResetCorrelationState(); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordDerivedFinding("incomplete", scanner.Finding{RuleID: "derived.rule"}); err != nil {
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
	counts, err := provider.Counts(context.Background(), "building-scan")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 0 {
		t.Fatalf("incomplete derived rows visible: %#v", counts)
	}
	items, err := provider.Findings(context.Background(), "building-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("incomplete derived page visible: %#v", items)
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

func TestProviderCountsAndBoundedSearchPage(t *testing.T) {
	path := makeFixtureDB(t, "scan-search")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	counts, err := provider.Counts(context.Background(), "scan-search")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Findings != 1 || counts.Credentials != 1 || counts.Correlations != 0 {
		t.Fatalf("unexpected persisted counts: %#v", counts)
	}
	page, err := provider.SearchPage(context.Background(), "scan-search", "synthetic", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 1 || len(page.Credentials) != 1 || page.PersistedRows != 2 {
		t.Fatalf("unexpected bounded search page: %#v", page)
	}
	if _, err := provider.SearchPage(context.Background(), "scan-search", "synthetic", PageSize+1); err == nil {
		t.Fatal("expected bounded search page validation")
	}
}

func TestProviderSearchPageAfterTraversesEveryPopulationWithoutDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "search-pages.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-pages", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 32, BatchSize: 32, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const total = PageSize + 17
	for index := 0; index < total; index++ {
		if err := state.RecordFinding(scanner.Finding{RuleID: "page.rule", RuleName: "Page Search", MatchedText: fmt.Sprintf("page-token-%04d", index), FilePath: fmt.Sprintf("evidence/%04d.txt", index)}); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: fmt.Sprintf("page-user-%04d", index), Value: fmt.Sprintf("page-token-%04d", index)}); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCorrelation(fmt.Sprintf("page-correlation-%04d", index), map[string]any{"payload": fmt.Sprintf("page-token-%04d", index)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now().UTC()); err != nil {
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
	seen := make(map[string]struct{}, total*3)
	var findingCursor, credentialCursor int64
	var correlationCursor string
	for pageNumber := 0; ; pageNumber++ {
		page, err := provider.SearchPageAfter(context.Background(), "scan-pages", "page-token", findingCursor, credentialCursor, correlationCursor, PageSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Findings {
			ref := findingRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate finding reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		for _, item := range page.Credentials {
			ref := credentialRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate credential reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		for _, item := range page.Correlations {
			ref := correlationRowRef(item)
			if _, exists := seen[ref]; exists {
				t.Fatalf("duplicate correlation reference on page %d: %s", pageNumber, ref)
			}
			seen[ref] = struct{}{}
		}
		if len(page.Findings) > 0 {
			findingCursor = page.FindingCursor
		}
		if len(page.Credentials) > 0 {
			credentialCursor = page.CredentialCursor
		}
		if len(page.Correlations) > 0 {
			correlationCursor = page.CorrelationCursor
		}
		if page.Done {
			break
		}
		if page.PersistedRows == 0 {
			t.Fatal("search continuation made no progress")
		}
	}
	if want := total * 3; len(seen) != want {
		t.Fatalf("search references = %d, want %d", len(seen), want)
	}
}

func TestCredentialGroupExpansionIsIndependentOfPageBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential-groups.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-groups", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 32, BatchSize: 32, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	const total = PageSize + 9
	for index := 0; index < total; index++ {
		if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "shared-user", Value: "shared-value", Path: fmt.Sprintf("group/%04d.ini", index), Host: "HOST", Share: "Share"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "unrelated-user", Value: "shared-value", Path: "unrelated.ini"}); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now().UTC()); err != nil {
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
	first, err := provider.CredentialsAfter(context.Background(), "scan-groups", 0, PageSize)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.CredentialsAfter(context.Background(), "scan-groups", first[len(first)-1].ID, PageSize)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := expandCredentialGroups(context.Background(), provider, "scan-groups", first)
	if err != nil {
		t.Fatal(err)
	}
	categories, _ := buildCategoriesWithAccounting("scan-groups", expanded, nil, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 || len(categories[0].Discoveries[0].PersistedRefs) != PageSize {
		t.Fatalf("first page group projection = categories=%d discoveries=%d refs=%d", len(categories), len(categories[0].Discoveries), len(categories[0].Discoveries[0].PersistedRefs))
	}
	expandedSecond, err := expandCredentialGroups(context.Background(), provider, "scan-groups", second)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSecond := retainCanonicalCredentialGroups(expandedSecond, second)
	secondCategories, _ := buildCategoriesWithAccounting("scan-groups", canonicalSecond, nil, nil)
	if len(secondCategories) != 1 || len(secondCategories[0].Discoveries) != 1 {
		t.Fatalf("second page should retain only unrelated canonical group: %#v", secondCategories)
	}
	if got := len(secondCategories[0].Discoveries[0].PersistedRefs); got != 1 {
		t.Fatalf("unrelated second-page group refs=%d, want 1", got)
	}
	matchedOnly, err := provider.SearchPage(context.Background(), "scan-groups", "group/0508.ini", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(matchedOnly.Credentials) != 1 {
		t.Fatalf("search matched credentials=%d, want 1", len(matchedOnly.Credentials))
	}
	matchedExpanded, err := expandCredentialGroups(context.Background(), provider, "scan-groups", matchedOnly.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	matchedCategories, _ := buildCategoriesWithAccounting("scan-groups", matchedExpanded, nil, nil)
	if len(matchedCategories) != 1 || len(matchedCategories[0].Discoveries) != 1 || len(matchedCategories[0].Discoveries[0].PersistedRefs) < PageSize {
		t.Fatalf("search relationship context lost: categories=%d discoveries=%d refs=%d", len(matchedCategories), len(matchedCategories[0].Discoveries), len(matchedCategories[0].Discoveries[0].PersistedRefs))
	}
}

func TestCredentialRelationshipPagesTraverseTenThousandRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-credential-group.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-large-group", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	const total = 10000
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < total; index++ {
		candidate := credentialanalysis.Candidate{CredentialType: "password", Identity: "large-user", Value: "large-value", Path: fmt.Sprintf("large/%05d.ini", index)}
		payload, err := json.Marshal(candidate)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var payloadObject map[string]any
		if err := json.Unmarshal(payload, &payloadObject); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		payloadObject["value"] = candidate.Value
		payload, err = json.Marshal(payloadObject)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec("INSERT INTO credentials(scan_id,credential_key,credential_type,identity,value,payload) VALUES(?,?,?,?,?,?)", "scan-large-group", fmt.Sprintf("password|large-user|%s|large-value", candidate.Path), candidate.CredentialType, candidate.Identity, candidate.Value, payload); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	seed, err := provider.CredentialsAfter(context.Background(), "scan-large-group", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 1 {
		t.Fatal("missing large-group seed")
	}
	if seed[0].Candidate.CredentialType != "password" || seed[0].Candidate.Identity != "large-user" || seed[0].Candidate.Value != "large-value" {
		t.Fatalf("unexpected seed candidate: %#v", seed[0].Candidate)
	}
	seen := map[string]struct{}{}
	after := int64(0)
	for {
		page, err := provider.RelatedCredentialsAfter(context.Background(), "scan-large-group", seed[0], after, PageSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page {
			ref := credentialRowRef(item)
			if _, duplicate := seen[ref]; duplicate {
				t.Fatalf("duplicate related reference %s", ref)
			}
			seen[ref] = struct{}{}
			after = item.ID
		}
		if len(page) < PageSize {
			break
		}
	}
	if len(seen) != total {
		t.Fatalf("related references=%d, want %d", len(seen), total)
	}
}

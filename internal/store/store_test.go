package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

var storeTestTime = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func openTestStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, Options{ScanID: "scan-synthetic", SnablrVersion: "test", Semantics: "semantics-synthetic", QueueSize: 32, BatchSize: 8, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestSQLiteStorePersistsLogicalStateAndReopens(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.RecordTarget("synthetic-host.test", "completed", storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordShare("synthetic-host.test", "SyntheticShare", "completed", storeTestTime); err != nil {
		t.Fatal(err)
	}
	key := "12:synthetic-host.test13:SyntheticShare22:packages/archive.zip"
	if err := s.RecordFile(key, "synthetic-host.test", "SyntheticShare", "packages/archive.zip", "partial", "semantics-synthetic", 42, storeTestTime, storeTestTime, storeTestTime, storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAccess("ctx-synthetic", key, "accessible", storeTestTime, storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordMember(key, "app/config.ini", "archive", "app/config.ini", "inspected", "packages/archive.zip!app/config.ini"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordMember(key, "wim:1:Windows/SAM", "wim", "Windows/SAM", "inspected", "synthetic.wim!Windows/SAM"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFinding(scanner.Finding{Host: "synthetic-host.test", Share: "SyntheticShare", FilePath: "packages/archive.zip!app/config.ini", RuleID: "synthetic.password", Category: "credentials"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticActual482!", Path: "packages/archive.zip!app/config.ini"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCorrelation("corr-synthetic", map[string]string{"kind": "archive-credential"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCorrelation("corr-synthetic", map[string]string{"kind": "archive-credential"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetScanStatus(StatusInterrupted, storeTestTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ScanStatus != string(StatusInterrupted) || snapshot.FileStatus[key] != "partial" || snapshot.MemberKeys[key+"\x00app/config.ini"] != "inspected" {
		t.Fatalf("logical parity snapshot lost state: %#v", snapshot)
	}
	if len(snapshot.CorrelationKeys) != 1 {
		t.Fatalf("correlation upsert is not idempotent: %#v", snapshot.CorrelationKeys)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	check := func(db *sql.DB) {
		var status string
		if err := db.QueryRow(`SELECT status FROM scans WHERE scan_id='scan-synthetic'`).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != string(StatusInterrupted) {
			t.Fatalf("scan status=%q", status)
		}
		for _, table := range []string{"targets", "shares", "files", "access_observations", "members", "findings", "credentials", "correlations"} {
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				t.Fatalf("table %s is empty", table)
			}
		}
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	check(db)
}

func TestSQLiteStoreRollsBackFailedBatch(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.enqueue(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO targets(scan_id,host,status,updated_at) VALUES(?,?,?,?)`, s.scanID, "synthetic-host.test", "partial", storeTestTime.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		return fmt.Errorf("synthetic transaction failure")
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err == nil {
		t.Fatal("expected failed batch to mark state store unhealthy")
	}
	_ = s.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM targets WHERE host='synthetic-host.test'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back batch left %d rows", count)
	}
}

func TestSQLiteStorePermissionsAndSidecars(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.RecordTarget("synthetic-host.test", "partial", storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s permissions=%o, want 600", candidate, info.Mode().Perm())
		}
	}
}

func TestResumeFileLookupUsesIdentityIndex(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT file_key FROM files WHERE scan_id=? AND host=? AND share=? AND path=?`, "scan-synthetic", "synthetic-host.test", "SyntheticShare", "missing")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var detail string
	used := false
	for rows.Next() {
		var id, parent, notused, text string
		if err := rows.Scan(&id, &parent, &notused, &text); err != nil {
			t.Fatal(err)
		}
		detail += text
		if strings.Contains(text, "files_identity_idx") {
			used = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatalf("resume lookup did not use identity index: %s", detail)
	}
}

func TestRemainingWorkLookupUsesStatusIndex(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT COUNT(*) FROM files WHERE scan_id=? AND status NOT IN ('completed','skipped_unchanged')`, "scan-synthetic")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var detail string
	used := false
	for rows.Next() {
		var id, parent, notused, text string
		if err := rows.Scan(&id, &parent, &notused, &text); err != nil {
			t.Fatal(err)
		}
		detail += text
		if strings.Contains(text, "files_status_idx") {
			used = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatalf("remaining-work query did not use status index: %s", detail)
	}
}

func TestSQLiteStoreScale100kFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test is skipped in short mode")
	}
	s, path := openTestStore(t)
	started := time.Now()
	for i := 0; i < 100_000; i++ {
		key := "file-" + strings.Repeat("0", 6-len(intString(i))) + intString(i)
		if err := s.RecordFile(key, "synthetic-host.test", "SyntheticShare", "files/"+key, "completed", "semantics-synthetic", int64(i), storeTestTime, storeTestTime, storeTestTime, storeTestTime); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	walSize := int64(0)
	if walInfo, err := os.Stat(path + "-wal"); err == nil {
		walSize = walInfo.Size()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	dbInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	jsonBytes, err := json.Marshal(make([]FileState, 100_000))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("100k files: %.0f records/sec, sqlite=%d bytes, WAL before close=%d bytes, equivalent metadata JSON=%d bytes", 100_000/time.Since(started).Seconds(), dbInfo.Size(), walSize, len(jsonBytes))
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM files WHERE status='completed'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 100_000 {
		t.Fatalf("file rows=%d, want 100000", count)
	}
}

func intString(value int) string { return strconv.Itoa(value) }

func TestAuthoritativeWriteFailureIsReportedWithoutCorruptingCommittedBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, Options{ScanID: "scan-failure", SnablrVersion: "test", Semantics: "semantics-synthetic", BatchSize: 1, FailAfterBatches: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordTarget("synthetic-host.test", "partial", storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordShare("synthetic-host.test", "SyntheticShare", "partial", storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err == nil {
		t.Fatal("expected injected authoritative write failure")
	}
	if s.Failure() == nil {
		t.Fatal("store did not retain authoritative failure")
	}
	if err := s.Close(); err == nil {
		t.Fatal("close should report authoritative failure")
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var targets int
	if err := db.QueryRow(`SELECT COUNT(*) FROM targets WHERE scan_id='scan-failure'`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	var shares int
	if err := db.QueryRow(`SELECT COUNT(*) FROM shares WHERE scan_id='scan-failure'`).Scan(&shares); err != nil {
		t.Fatal(err)
	}
	if targets != 1 || shares != 0 {
		t.Fatalf("committed batch integrity lost: targets=%d shares=%d", targets, shares)
	}
}

func TestSQLiteStoreScopeExclusionsNormalizeAndRespectBoundaries(t *testing.T) {
	s, path := openTestStore(t)
	defer s.Close()
	if err := s.RecordScopeExclusion(ScopeExclusionFolder, "HOST.TEST", `\\Share`, `\\1\\2\\3`, storeTestTime); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"1/2/3", true},
		{"1/2/3/Nested", true},
		{"1/2/30", false},
		{"1/2", false},
	} {
		got, err := s.IsScopeExcluded(ScopeExclusionFolder, "host.test", "share", tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("folder exclusion %q = %v, want %v", tc.path, got, tc.want)
		}
	}
	if err := s.RecordScopeExclusion(ScopeExclusionShare, "host.test", "share", "ignored", storeTestTime); err != nil {
		t.Fatal(err)
	}
	got, err := s.IsScopeExcluded(ScopeExclusionShare, "HOST.TEST", "\\SHARE\\", "")
	if err != nil || !got {
		t.Fatalf("share exclusion = %v, err=%v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, _, reused, err := OpenLatestForReuse(path, ResumeOptions{ExpectedSemantics: "semantics-synthetic"})
	if err != nil || !reused {
		t.Fatalf("reopen exclusion state: reused=%v err=%v", reused, err)
	}
	defer reopened.Close()
	got, err = reopened.IsScopeExcluded(ScopeExclusionFolder, "host.test", "share", "1/2/3/Nested")
	if err != nil || !got {
		t.Fatalf("persisted folder exclusion = %v, err=%v", got, err)
	}
}

func TestSQLiteStoreScopeExclusionFailureDoesNotClaimSuccess(t *testing.T) {
	s, _ := openTestStore(t)
	defer s.Close()
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	s.failAfterBatches = s.committedBatches
	if err := s.RecordScopeExclusion(ScopeExclusionShare, "host", "share", "", storeTestTime); err == nil {
		t.Fatal("expected authoritative exclusion write failure")
	}
}

func TestSQLiteStoreFreshScanScopeDoesNotInheritExclusions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := Open(path, Options{ScanID: "scan-first", Semantics: "semantics-synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RecordScopeExclusion(ScopeExclusionShare, "host", "share", "", storeTestTime); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(path, Options{ScanID: "scan-force", Semantics: "semantics-synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if excluded, err := fresh.IsScopeExcluded(ScopeExclusionShare, "host", "share", ""); err != nil || excluded {
		t.Fatalf("fresh scan inherited exclusion: excluded=%v err=%v", excluded, err)
	}
}

func TestRecordCredentialPersistsBoundedCrossFileCorrelation(t *testing.T) {
	t.Parallel()
	state, _ := openTestStore(t)
	defer state.Close()
	for _, candidate := range []credentialanalysis.Candidate{
		{CredentialType: "password", Identity: "synthetic\\svc", Value: "first-value", Host: "host", Share: "share", Path: "one.ini", Verification: credentialanalysis.Confirmed},
		{CredentialType: "password", Identity: "synthetic\\svc", Value: "second-value", Host: "host", Share: "share", Path: "two.ini", Verification: credentialanalysis.Confirmed},
		{CredentialType: "password", Identity: "other-user", Value: "second-value", Host: "host", Share: "share", Path: "other.ini", Verification: credentialanalysis.Confirmed},
	} {
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.CorrelationKeys) != 1 {
		t.Fatalf("got %d correlation rows, want one: %#v", len(snapshot.CorrelationKeys), snapshot.CorrelationKeys)
	}
}

type credentialSinkFindingStub struct{}

func (credentialSinkFindingStub) WriteFinding(scanner.Finding) error { return nil }
func (credentialSinkFindingStub) Close() error                       { return nil }

func TestSQLiteSinkCredentialWriteSuccessIsPersisted(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	defer store.Close()
	sink := WrapSink(credentialSinkFindingStub{}, store)
	candidate := credentialanalysis.Candidate{
		CredentialType: "password",
		Identity:       "r4a-user",
		Value:          "R4A-Synthetic-Pass-482!",
		Path:           "r4a/credentials.ini",
	}
	if err := sink.RecordCredentialCandidate(candidate); err != nil {
		t.Fatalf("RecordCredentialCandidate returned error: %v", err)
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE identity=? AND value=?`, candidate.Identity, candidate.Value).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("persisted credential count=%d, want 1", count)
	}
}

func TestSQLiteSinkPrivateKeyEvidenceAndMetadataArePersisted(t *testing.T) {
	t.Parallel()

	state, path := openTestStore(t)
	defer state.Close()
	sink := WrapSink(credentialSinkFindingStub{}, state)
	candidate := credentialanalysis.Candidate{
		Verification:    credentialanalysis.Confirmed,
		CredentialType:  "private_key",
		Value:           "SYNTHETIC-PRIVATE-KEY-BODY",
		KeyFormat:       "PEM",
		KeyAlgorithm:    "EC",
		KeyStatus:       "confirmed",
		ValidationBasis: "private_key_structural_parser",
		Path:            "exports/customer-key",
	}
	if err := sink.RecordCredentialCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value, payload string
	if err := db.QueryRow(`SELECT value,payload FROM credentials WHERE credential_type=?`, "private_key").Scan(&value, &payload); err != nil {
		t.Fatal(err)
	}
	if value != candidate.Value || !strings.Contains(payload, candidate.Value) || !strings.Contains(payload, candidate.KeyStatus) {
		t.Fatalf("private-key evidence or metadata was not preserved: value=%q payload=%q", value, payload)
	}
}

func TestSQLiteSinkCredentialWriteFailureIsReturned(t *testing.T) {
	t.Parallel()

	store, _ := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("closing test store: %v", err)
	}
	sink := WrapSink(credentialSinkFindingStub{}, store)
	err := sink.RecordCredentialCandidate(credentialanalysis.Candidate{
		CredentialType: "password",
		Identity:       "r4a-user",
		Value:          "R4A-Synthetic-Pass-482!",
		Path:           "r4a/credentials.ini",
	})
	if err == nil {
		t.Fatal("expected closed SQLite store error")
	}
	if !strings.Contains(err.Error(), "persist credential candidate") || !strings.Contains(err.Error(), "sqlite state store is closed") {
		t.Fatalf("error=%q, want operation context and underlying error", err)
	}
}

func TestSQLiteSinkFailureAfterEarlierCommittedWriteRemainsObservable(t *testing.T) {
	t.Parallel()

	store, path := openTestStore(t)
	sink := WrapSink(credentialSinkFindingStub{}, store)
	first := credentialanalysis.Candidate{CredentialType: "password", Identity: "first", Value: "First-R4A!", Path: "r4a/first.ini"}
	if err := sink.RecordCredentialCandidate(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	secondErr := sink.RecordCredentialCandidate(credentialanalysis.Candidate{CredentialType: "password", Identity: "second", Value: "Second-R4A!", Path: "r4a/second.ini"})
	if secondErr == nil {
		t.Fatal("expected second write error")
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE identity=?`, first.Identity).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("earlier committed credential count=%d, want 1", count)
	}
}

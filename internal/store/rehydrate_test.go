package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/credentialanalysis"
)

func TestOpenForResumeRehydratesLogicalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.sqlite")
	shadow, err := Open(path, Options{ScanID: "synthetic-scan", Semantics: "semantics-a", BatchSize: 8, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := shadow.RecordTarget("synthetic-host", "completed", at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordShare("synthetic-host", "SyntheticShare", "partial", at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordFile("file-1", "synthetic-host", "SyntheticShare", "done.txt", "completed", "semantics-a", 12, at, at, at, at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordFile("file-2", "synthetic-host", "SyntheticShare", "pending.txt", "failed", "semantics-a", 9, at, at, at, at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticResume482!", Host: "synthetic-host", Share: "SyntheticShare", Path: "done.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordMember("file-1", "member-1", "archive", "config/app.ini", "completed", "packages/synthetic.zip"); err != nil {
		t.Fatal(err)
	}
	if err := shadow.RecordMember("file-1", "member-2", "wim", "Windows/System32/synthetic.dll", "partial", "image=1"); err != nil {
		t.Fatal(err)
	}
	if err := shadow.SetScanStatus(StatusInterrupted, at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, state, err := OpenForResume(path, ResumeOptions{ExpectedSemantics: "semantics-a", MaterializeFiles: true, BatchSize: 8, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if state.ScanID != "synthetic-scan" || state.Status != string(StatusInterrupted) {
		t.Fatalf("unexpected state: %+v", state)
	}
	if !state.SemanticsMatch || len(state.Files) != 2 || len(state.Targets) != 1 || len(state.Shares) != 1 {
		t.Fatalf("incomplete state: %+v", state)
	}
	if !state.FileWasCompleted("synthetic-host", "SyntheticShare", "done.txt") {
		t.Fatal("completed file was not reusable")
	}
	if state.FileWasCompleted("synthetic-host", "SyntheticShare", "pending.txt") {
		t.Fatal("failed file became reusable")
	}
	if len(state.Credentials) != 1 || state.Credentials[0].Value != "SyntheticResume482!" {
		t.Fatalf("credential value was not rehydrated: %+v", state.Credentials)
	}
	if len(state.Members) != 2 || state.Members[0].MemberPath == "" || state.Members[1].Status != "partial" {
		t.Fatalf("member state was not rehydrated: %+v", state.Members)
	}
	if err := reopened.SetScanStatus(StatusCompleted, at); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenForResumeRejectsChangedSemanticsAndUnsupportedSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.sqlite")
	shadow, err := Open(path, Options{ScanID: "synthetic-scan", Semantics: "semantics-a", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := shadow.Close(); err != nil {
		t.Fatal(err)
	}
	_, state, err := OpenForResume(path, ResumeOptions{ExpectedSemantics: "semantics-b"})
	if err != nil {
		t.Fatal(err)
	}
	if state.SemanticsMatch {
		t.Fatal("changed semantics incorrectly marked compatible")
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE metadata SET value='999' WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, _, err := OpenForResume(path, ResumeOptions{}); err == nil {
		t.Fatal("unsupported schema was accepted")
	}
}

func TestOpenForResumeScaleSyntheticFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scale.sqlite")
	shadow, err := Open(path, Options{ScanID: "scale-scan", Semantics: "scale-semantics", BatchSize: 512, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	for index := 0; index < 100_000; index++ {
		if err := shadow.RecordFile(
			"file-"+itoa(index), "synthetic-host", "SyntheticShare",
			"file-"+itoa(index)+".dat", "completed", "scale-semantics", int64(index), at, at, at, at,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := shadow.Close(); err != nil {
		t.Fatal(err)
	}
	_, state, err := OpenForResume(path, ResumeOptions{ExpectedSemantics: "scale-semantics", MaterializeFiles: true, BatchSize: 512, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Files) != 100_000 {
		t.Fatalf("rehydrated %d files, want 100000", len(state.Files))
	}
}

func TestOpenForResumeMillionFilesMeasurement(t *testing.T) {
	if os.Getenv("SNABLR_SQLITE_MILLION") != "1" {
		t.Skip("set SNABLR_SQLITE_MILLION=1 for the local scale measurement")
	}
	path := filepath.Join(t.TempDir(), "million.sqlite")
	started := time.Now()
	shadow, err := Open(path, Options{ScanID: "million-scan", Semantics: "million-semantics", QueueSize: 4096, BatchSize: 1024, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1_000_000; index++ {
		status := "completed"
		if index%11 == 0 {
			status = "failed"
		} else if index%17 == 0 {
			status = "partial"
		}
		if err := shadow.RecordFile("million-"+itoa(index), "synthetic-host-"+itoa(index%32), "SyntheticShare-"+itoa(index%64), "file-"+itoa(index)+".dat", status, "million-semantics", int64(index%8192), storeTestTime, storeTestTime, storeTestTime, storeTestTime); err != nil {
			t.Fatal(err)
		}
	}
	if err := shadow.Flush(); err != nil {
		t.Fatal(err)
	}
	writeDuration := time.Since(started)
	dbSize := fileSize(path)
	walSize := fileSize(path + "-wal")
	shmSize := fileSize(path + "-shm")
	before := memoryBytes()
	openStarted := time.Now()
	reopened, state, err := OpenForResume(path, ResumeOptions{ExpectedSemantics: "million-semantics", MaterializeFiles: false, BatchSize: 1024, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	openDuration := time.Since(openStarted)
	peak := memoryBytes()
	remainingStarted := time.Now()
	remaining, err := reopened.RemainingFileCount()
	if err != nil {
		t.Fatal(err)
	}
	remainingDuration := time.Since(remainingStarted)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	cleanDBSize := fileSize(path)
	t.Logf("million rows=%d write=%s db=%d wal=%d shm=%d open=%s remaining=%d remaining_query=%s memory_before=%d memory_after=%d state_files=%d clean_db=%d", 1_000_000, writeDuration, dbSize, walSize, shmSize, openDuration, remaining, remainingDuration, before, peak, len(state.Files), cleanDBSize)
	if remaining == 0 {
		t.Fatal("scale fixture unexpectedly has no remaining work")
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
func memoryBytes() uint64 {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.Alloc
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

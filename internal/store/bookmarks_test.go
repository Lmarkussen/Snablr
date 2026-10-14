package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func TestBookmarksPersistToggleAndRemainFileCentric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bookmarks.db")
	state, err := Open(path, Options{ScanID: "bookmark-scan", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := state.RecordFile("file-a", "synthetic-host", "share-a", "config.txt", "complete", "semantics", 1, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordFile("file-b", "synthetic-host", "share-b", "config.txt", "complete", "semantics", 1, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	bookmark, added, err := state.ToggleBookmark(context.Background(), "synthetic-host", "share-a", "config.txt")
	if err != nil || !added || bookmark.FileKey != "file-a" {
		t.Fatalf("bookmark add failed: %+v added=%t err=%v", bookmark, added, err)
	}
	if got, err := state.ListBookmarks(context.Background(), 100, 0); err != nil || len(got) != 1 {
		t.Fatalf("unexpected bookmark list: %#v err=%v", got, err)
	}
	if bookmarked, err := state.IsBookmarked(context.Background(), "file-a"); err != nil || !bookmarked {
		t.Fatalf("IsBookmarked failed: bookmarked=%t err=%v", bookmarked, err)
	}
	if _, added, err := state.ToggleBookmarkKey(context.Background(), "file-a"); err != nil || added {
		t.Fatalf("second toggle should remove bookmark: added=%t err=%v", added, err)
	}
	if err := state.RemoveBookmark(context.Background(), "file-a"); err != nil {
		t.Fatal(err)
	}
	if bookmarked, err := state.IsBookmarked(context.Background(), "file-a"); err != nil || bookmarked {
		t.Fatalf("RemoveBookmark failed: bookmarked=%t err=%v", bookmarked, err)
	}
	if _, added, err := state.ToggleBookmarkKey(context.Background(), "file-a"); err != nil || !added {
		t.Fatalf("re-add failed: added=%t err=%v", added, err)
	}
	if _, added, err := state.ToggleBookmark(context.Background(), "synthetic-host", "share-b", "config.txt"); err != nil || !added {
		t.Fatalf("same filename on another share was not independent: added=%t err=%v", added, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, Options{ScanID: "bookmark-scan", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.ListBookmarks(context.Background(), 100, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("bookmarks did not survive reopen: %#v err=%v", got, err)
	}
}

func TestBookmarkDetailsIncludeBoundedRelatedFindingsAndCredentials(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "details.db"), Options{ScanID: "details-scan", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	if err := state.RecordFile("file-1", "host", "share", "lars.txt", "complete", "semantics", 1, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordFinding(scanner.Finding{Host: "host", Share: "share", FilePath: "lars.txt", RuleID: "synthetic.password", Category: "credentials", MatchedText: "SyntheticSecret"}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticSecret", Path: "lars.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, added, err := state.ToggleBookmarkKey(context.Background(), "file-1"); err != nil || !added {
		t.Fatal(err)
	}
	detail, err := state.BookmarkDetails(context.Background(), "file-1")
	if err != nil || len(detail.Findings) != 1 || len(detail.Credentials) != 1 || detail.Credentials[0].Value != "SyntheticSecret" {
		t.Fatalf("unexpected bookmark details: %+v err=%v", detail, err)
	}
}

func TestBookmarkSchemaMigratesFromVersionOneWithoutDataLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration.db")
	state, err := Open(path, Options{ScanID: "migration-scan", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := state.RecordFile("file-1", "host", "share", "file.txt", "complete", "semantics", 1, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE metadata SET value='1' WHERE key='schema_version'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path, Options{ScanID: "migration-scan", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var count int
	if err := migrated.db.QueryRow(`SELECT COUNT(*) FROM files WHERE file_key='file-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("existing file data was not preserved: count=%d err=%v", count, err)
	}
	if _, err := migrated.db.Exec(`SELECT file_key FROM bookmarks LIMIT 1`); err != nil {
		t.Fatalf("bookmark table was not migrated: %v", err)
	}
}

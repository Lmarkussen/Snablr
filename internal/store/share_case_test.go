package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/scanner"
)

// The file inventory keeps hosts and shares in lowercase, while findings name
// them as found (C$, FileServer01). Bookmarks and search still link the two.
func TestFindingsAndFilesLinkAcrossShareCase(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "case.db"), Options{ScanID: "case-scan", Semantics: "semantics", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	if err := state.RecordFile("file-1", "fileserver01", "c$", "Users/alice/notes.txt", "completed", "semantics", 10, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordFinding(scanner.Finding{RuleID: "synthetic.rule", Category: "credentials", Host: "FileServer01", Share: "C$", FilePath: "Users/alice/notes.txt", Match: "case-needle"}); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, added, err := state.ToggleBookmark(context.Background(), "FileServer01", "C$", "Users/alice/notes.txt"); err != nil || !added {
		t.Fatalf("bookmark from finding: added=%v err=%v", added, err)
	}
	detail, err := state.BookmarkDetails(context.Background(), "file-1")
	if err != nil || len(detail.Findings) != 1 {
		t.Fatalf("bookmark details: findings=%d err=%v", len(detail.Findings), err)
	}
	results, err := state.Search(context.Background(), "synthetic.rule", SearchOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	linked := false
	for _, result := range results {
		if result.Type == SearchResultFinding && result.BookmarkKey == "file-1" {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("search result not linked to its file: %+v", results)
	}
}

package store

import (
	"context"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func TestSearchQueriesPersistedRowsWithoutMaterializingInventory(t *testing.T) {
	path := t.TempDir() + "/snablr.db"
	state, err := Open(path, Options{ScanID: "search-test", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	if err := state.RecordFile("file-1", "FS01", "Users", `\\FS01\Users\lars\notes.txt`, "complete", "semantics", 12, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordFinding(scanner.Finding{RuleID: "password-rule", Category: "credentials", Host: "FS01", Share: "Users", FilePath: `\\FS01\Users\config.ini`, Snippet: "synthetic evidence lars"}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordCredential(credentialanalysis.Candidate{CredentialType: "password", Identity: "lars", Value: "synthetic-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	results, err := state.Search(context.Background(), "lars", SearchOptions{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d search results, want 3: %#v", len(results), results)
	}
	if results[0].Type != SearchResultCredential && results[1].Type != SearchResultCredential && results[2].Type != SearchResultCredential {
		t.Fatalf("credential match missing: %#v", results)
	}
}

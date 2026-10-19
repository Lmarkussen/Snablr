package store

import (
	"context"
	"fmt"
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

func TestSearchReadsWhileWriterCommits(t *testing.T) {
	state, err := Open(t.TempDir()+"/concurrent.db", Options{ScanID: "concurrent", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			if err := state.RecordFile(fmt.Sprintf("file-%d", i), "FS01", "Users", fmt.Sprintf("folder/%d.txt", i), "complete", "semantics", 1, now, now, now, now); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- state.Flush()
	}()
	for i := 0; i < 100; i++ {
		if _, err := state.Search(context.Background(), "folder", SearchOptions{Limit: 10}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestSearchOmitsSuppressedCredentialCandidatesButKeepsValidMaterial(t *testing.T) {
	t.Parallel()
	state, err := Open(t.TempDir()+"/search-filter.db", Options{ScanID: "search-filter", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	candidates := []credentialanalysis.Candidate{
		{CredentialType: "password", Identity: "masked-user", Value: "********"},
		{CredentialType: "secret", Identity: "", Value: "synthetic"},
		{CredentialType: "password", Value: "Odd punctuation !? [value]", Path: "same.txt"},
		{CredentialType: "password", Identity: "valid-user", Value: "Odd punctuation !? [value]"},
		{CredentialType: "password", Identity: "other-user", Value: "Odd punctuation !? [value]", Path: "other.txt"},
		{CredentialType: "nt_hash", Identity: "hash-user", Value: "0123456789abcdef0123456789abcdef"},
		{CredentialType: "netntlmv2", Identity: "hash-user", Value: "hash-capture-material"},
	}
	for _, candidate := range candidates {
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}

	results, err := state.Search(context.Background(), "user", SearchOptions{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Type == SearchResultCredential && (result.Title == "masked-user" || result.Title == "secret") {
			t.Fatalf("suppressed credential appeared in search: %#v", result)
		}
	}
	seenValid, seenHash := false, false
	for _, result := range results {
		if result.Type != SearchResultCredential {
			continue
		}
		if result.Title == "valid-user" {
			seenValid = true
		}
		if result.Title == "hash-user" {
			seenHash = true
		}
	}
	if !seenValid || !seenHash {
		t.Fatalf("valid credential/hash missing from search: %#v", results)
	}
	passwordRows := 0
	for _, result := range results {
		if result.Type == SearchResultCredential && result.Context == "password" {
			passwordRows++
		}
	}
	if passwordRows != 2 {
		t.Fatalf("same-source identity variants should merge while unrelated users remain distinct, got %d rows: %#v", passwordRows, results)
	}
}

func TestSearchPaginationCountsOnlyVisibleCredentials(t *testing.T) {
	t.Parallel()
	state, err := Open(t.TempDir()+"/search-pagination.db", Options{ScanID: "search-pagination", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	for _, candidate := range []credentialanalysis.Candidate{
		{CredentialType: "password", Identity: "masked-1", Value: "********"},
		{CredentialType: "password", Identity: "masked-2", Value: "${PASSWORD}"},
		{CredentialType: "password", Identity: "visible", Value: "A valid unusual ! password"},
	} {
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	results, err := state.Search(context.Background(), "password", SearchOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Title != "visible" {
		t.Fatalf("visible credential pagination failed: %#v", results)
	}
}

package findings

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

// Findings whose evidence the scan stored once in the evidence table show and
// search in the Finder with their whole evidence.
func TestFinderShowsAndSearchesSharedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	state, err := store.Open(path, store.Options{ScanID: "shared-scan", SnablrVersion: "test", Semantics: "synthetic", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	file := strings.Repeat("{\"Server\": \"db.example.test\", \"Database\": \"Synthetic\"}\n", 512) + "finder-needle-in-file"
	for i := 0; i < 3; i++ {
		if err := state.RecordFinding(scanner.Finding{RuleID: "dbinspect.infrastructure.structured_config", Category: "database-infrastructure", Host: "fileserver.example.test", Share: "share", FilePath: "config.json", Match: fmt.Sprintf("endpoint-%d", i), MatchedText: file, Snippet: file, Context: file}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now().UTC()); err != nil {
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
	page, err := provider.Findings(context.Background(), "shared-scan", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 3 {
		t.Fatalf("Finder listed %d findings, want 3", len(page))
	}
	detail, err := provider.Finding(context.Background(), "shared-scan", page[2].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Finding.MatchedText != file || detail.Finding.Context != file || detail.Finding.Match != "endpoint-2" {
		t.Fatal("Finder detail lost the stored evidence")
	}
	results, err := provider.SearchPage(context.Background(), "shared-scan", "FINDER-NEEDLE-IN-FILE", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results.Findings) != 3 {
		t.Fatalf("Finder search found %d findings by evidence text, want 3", len(results.Findings))
	}
}

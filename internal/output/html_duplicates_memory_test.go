package output

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

// Duplicates whose evidence is a whole file stream one at a time: listing a
// group's duplicates must not hold all of their payloads in SQLite memory.
func TestHTMLReportIndexStreamsLargeDuplicatesWithinBoundedMemory(t *testing.T) {
	evidence := strings.Repeat("Server=db.example.test;Database=Synthetic;\n", 24<<10)
	base := sampleFinding()
	base.MatchedText, base.Snippet, base.Context = evidence, evidence, evidence
	var findings []scanner.Finding
	for i := 0; i < 24; i++ {
		f := base
		f.FilePath = fmt.Sprintf("Policies/Copy-%02d/Groups.xml", i)
		findings = append(findings, f)
	}
	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	var group HTMLReportGroup
	if err := index.ForEachGroup(context.Background(), true, func(g HTMLReportGroup) error {
		group = g
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if group.DuplicateCount != 23 {
		t.Fatalf("duplicates=%d, want 23", group.DuplicateCount)
	}

	// The duplicates' payloads total about 23 x 3 MB; allow SQLite a small
	// fraction of that.
	limit := int64(24 << 20)
	if _, err := index.db.Exec(fmt.Sprintf("PRAGMA hard_heap_limit=%d", limit)); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = index.db.Exec("PRAGMA hard_heap_limit=0") }()

	var paths []string
	if err := index.ForEachDuplicate(context.Background(), group.Key, func(f scanner.Finding) error {
		if f.MatchedText != evidence {
			return fmt.Errorf("duplicate %s lost its evidence", f.FilePath)
		}
		paths = append(paths, f.FilePath)
		return nil
	}); err != nil {
		t.Fatalf("listing duplicates within %d bytes of SQLite memory: %v", limit, err)
	}
	if len(paths) != 23 {
		t.Fatalf("listed %d duplicates, want 23", len(paths))
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1] > paths[i] {
			t.Fatalf("duplicates not in path order: %v", paths)
		}
	}
}

package output

import (
	"strings"
	"testing"

	"snablr/internal/scanner"
)

// A finding whose evidence is a whole file gets a deduplication key of
// bounded size that still tells apart findings exactly as the evidence does.
func TestReportFindingDedupKeyBoundedForWholeFileEvidence(t *testing.T) {
	file := strings.Repeat("Server=db.example.test;Database=Synthetic;\n", 32<<10)
	finding := func(evidence string) scanner.Finding {
		return scanner.Finding{RuleID: "dbinspect.infrastructure.structured_config", Category: "database-infrastructure", Host: "fileserver.example.test", Share: "share", FilePath: "config.json", MatchedText: evidence, MatchedTextRedacted: evidence, ObservationID: "structured:0:x"}
	}
	key := reportFindingDedupKey(finding(file))
	if len(key) > 2*reportDedupEvidenceMax {
		t.Fatalf("dedup key is %d bytes for %d bytes of evidence", len(key), len(file))
	}
	if reportFindingDedupKey(finding(strings.ToUpper(file))) != key {
		t.Fatal("evidence differing only in case gives a different key")
	}
	if reportFindingDedupKey(finding(file+"x")) == key {
		t.Fatal("different evidence gives the same key")
	}
	other := strings.Repeat("Server=db.example.test;Database=Other;\n", 32<<10)
	if (reportFindingDedupKey(finding(other)) < key) != (strings.ToLower(other) < strings.ToLower(file)) {
		t.Fatal("keys no longer sort as their evidence does")
	}
	short := finding("Server=db.example.test;Database=Synthetic")
	if !strings.Contains(reportFindingDedupKey(short), "server=db.example.test;database=synthetic") {
		t.Fatalf("short evidence no longer keyed verbatim: %q", reportFindingDedupKey(short))
	}
}

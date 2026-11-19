package output

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

func wholeFileFindings(count int) ([]scanner.Finding, string) {
	evidence := strings.Repeat("{\"Server\": \"db.example.test\", \"Database\": \"Synthetic\"}\n", 8<<10)
	base := sampleFinding()
	base.MatchedText, base.MatchedTextRedacted, base.Snippet, base.Context, base.ContextRedacted = evidence, evidence, evidence, evidence, evidence
	findings := make([]scanner.Finding, 0, count)
	for i := 0; i < count; i++ {
		f := base
		f.FilePath = fmt.Sprintf("Configs/Copy-%02d/config.json", i)
		f.Match = fmt.Sprintf("endpoint-%02d", i)
		findings = append(findings, f)
	}
	return findings, evidence
}

// The HTML report index keeps a whole file used as evidence once, and every
// read gives the evidence back.
func TestHTMLReportIndexKeepsWholeFileEvidenceOnce(t *testing.T) {
	findings, evidence := wholeFileFindings(20)
	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	var bodies, payloadBytes int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM report_evidence`).Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if err := index.db.QueryRow(`SELECT SUM(length(payload)) FROM observations`).Scan(&payloadBytes); err != nil {
		t.Fatal(err)
	}
	if bodies != 1 || payloadBytes > 20*4096 {
		t.Fatalf("evidence rows=%d, observation payload bytes=%d for %d bytes of evidence", bodies, payloadBytes, len(evidence))
	}
	var group HTMLReportGroup
	if err := index.ForEachGroup(context.Background(), true, func(g HTMLReportGroup) error {
		group = g
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	canonical, err := index.Canonical(context.Background(), group.Key)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.MatchedText != evidence || canonical.ContextRedacted != evidence {
		t.Fatal("canonical finding lost its evidence")
	}
	duplicates := 0
	if err := index.ForEachDuplicate(context.Background(), group.Key, func(f scanner.Finding) error {
		duplicates++
		if f.Snippet != evidence || f.Context != evidence {
			return fmt.Errorf("duplicate %s lost its evidence", f.FilePath)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if duplicates == 0 {
		t.Fatal("no duplicates listed")
	}
}

// The JSON report state keeps a whole file used as evidence once, and the
// written report carries the evidence, never a reference to it.
func TestJSONReportStateKeepsWholeFileEvidenceOnce(t *testing.T) {
	findings, evidence := wholeFileFindings(20)
	state, err := newJSONSQLiteState()
	if err != nil {
		t.Fatal(err)
	}
	defer state.close()
	ctx := context.Background()
	for _, f := range findings {
		if err := state.ingest(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	var bodies, payloadBytes int
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM report_evidence`).Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if err := state.db.QueryRow(`SELECT (SELECT SUM(length(payload)) FROM report_findings) + (SELECT SUM(length(payload)) FROM report_fingerprints)`).Scan(&payloadBytes); err != nil {
		t.Fatal(err)
	}
	if bodies != 1 || payloadBytes > 40*4096 {
		t.Fatalf("evidence rows=%d, payload bytes=%d for %d bytes of evidence", bodies, payloadBytes, len(evidence))
	}
	var out bytes.Buffer
	if err := state.writeFindings(ctx, &out, false, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), reportEvidencePrefix) {
		t.Fatal("written report contains an evidence reference")
	}
	encodedEvidence := strings.ReplaceAll(strings.ReplaceAll(evidence, "\"", "\\\""), "\n", "\\n")
	if got := strings.Count(out.String(), encodedEvidence); got < 20 {
		t.Fatalf("written report carries the evidence %d times, want every finding's", got)
	}
}

// Duplicate-group keys built from long evidence are stored bounded in the
// HTML report index, and still group exactly as the full keys do.
func TestHTMLReportIndexBoundsLongGroupKeys(t *testing.T) {
	text := func(word string) string { return strings.Repeat(word+" synthetic review text ", 180) }
	finding := func(path, evidence string) scanner.Finding {
		return scanner.Finding{RuleID: "synthetic.review", RuleName: "Synthetic", Category: "review", Severity: "low", Host: "fileserver.example.test", Share: "share", FilePath: path, Match: "synthetic", MatchedText: evidence, Snippet: evidence}
	}
	findings := []scanner.Finding{
		finding("a.txt", text("alpha")),
		finding("b.txt", text("alpha")),
		finding("c.txt", text("bravo")),
	}
	if len(reportDuplicateGroupKey(findings[0])) <= indexedGroupKeyMax {
		t.Fatalf("test key is only %d bytes", len(reportDuplicateGroupKey(findings[0])))
	}
	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	var longest, groups int
	if err := index.db.QueryRow(`SELECT MAX(length(group_key)), COUNT(DISTINCT group_key) FROM observations`).Scan(&longest, &groups); err != nil {
		t.Fatal(err)
	}
	if longest > indexedGroupKeyMax+72 {
		t.Fatalf("index stores group keys of %d bytes", longest)
	}
	if groups != 2 {
		t.Fatalf("groups=%d, want the two distinct evidences", groups)
	}
}

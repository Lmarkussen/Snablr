package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/scanner"
)

// Findings that carry the same whole file as evidence store that file once,
// and every reader still sees each finding's original payload.
func TestFindingsStoreSharedEvidenceOnce(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "evidence.db"), Options{ScanID: "evidence-scan", Semantics: "semantics", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	file := strings.Repeat("{\"Server\": \"db.example.test\", \"Database\": \"Synthetic<&>\"}\n", 2048) + "needle-in-evidence æøå"
	var written []scanner.Finding
	for i := 0; i < 30; i++ {
		f := scanner.Finding{
			RuleID: "dbinspect.infrastructure.structured_config", Category: "database-infrastructure", Host: "fileserver.example.test", Share: "share",
			FilePath: "config.json", Match: fmt.Sprintf("endpoint-%d", i), ObservationID: fmt.Sprintf("structured:%d", i),
			MatchedText: file, MatchedTextRedacted: file, Snippet: file, Context: file, ContextRedacted: file,
			Tags: []string{"database"},
		}
		written = append(written, f)
		if err := state.RecordFinding(f); err != nil {
			t.Fatal(err)
		}
		if err := state.RecordCorrelationState("backup", "group", fmt.Sprintf("slot-%d", i), i, 1, f.FilePath, f); err != nil {
			t.Fatal(err)
		}
	}
	small := scanner.Finding{RuleID: "synthetic.small", FilePath: "small.txt", Match: "x", MatchedText: "password=short", Snippet: "password=short"}
	written = append(written, small)
	if err := state.RecordFinding(small); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}

	var bodies, stored int
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM evidence`).Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if bodies != 1 {
		t.Fatalf("evidence rows=%d, want the file once", bodies)
	}
	if err := state.db.QueryRow(`SELECT COALESCE(SUM(length(payload)),0) FROM finding_rows`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored > 30*4096 {
		t.Fatalf("finding rows hold %d payload bytes for evidence of %d bytes", stored, len(file))
	}

	rows, err := state.db.Query(`SELECT fingerprint, payload FROM findings ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for rows.Next() {
		var fingerprint string
		var payload []byte
		if err := rows.Scan(&fingerprint, &payload); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(written[index])
		if string(payload) != string(want) {
			t.Fatalf("finding %d payload differs from the original", index)
		}
		if fingerprint != payloadFingerprint(want) || fingerprint != FindingFingerprint(written[index]) {
			t.Fatalf("finding %d fingerprint changed", index)
		}
		index++
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if index != len(written) {
		t.Fatalf("read %d findings, want %d", index, len(written))
	}

	best, ok, err := state.BestCorrelationState(context.Background(), "backup", "group", "slot-29")
	if err != nil || !ok {
		t.Fatalf("correlation candidate: ok=%v err=%v", ok, err)
	}
	if best.MatchedText != file || best.ContextRedacted != file || best.Match != "endpoint-29" {
		t.Fatal("correlation candidate lost its evidence")
	}

	results, err := state.Search(context.Background(), "NEEDLE-IN-EVIDENCE ÆØÅ", SearchOptions{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, result := range results {
		if result.Type == SearchResultEvidence && result.Source == "config.json" {
			matched++
		}
	}
	if matched == 0 {
		t.Fatal("search no longer finds text inside stored evidence")
	}
}

// Rewriting a finding through the findings view keeps it readable: such
// writes store the payload as given.
func TestFindingsViewAcceptsDirectWrites(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "direct.db"), Options{ScanID: "direct-scan", Semantics: "semantics", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	file := strings.Repeat("synthetic evidence line\n", 1024)
	if err := state.RecordFinding(scanner.Finding{RuleID: "synthetic.rule", FilePath: "a.txt", Match: "m", MatchedText: file}); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := state.db.Exec(`UPDATE findings SET payload=replace(payload,'synthetic evidence','rewritten evidence') WHERE scan_id='direct-scan'`); err != nil {
		t.Fatal(err)
	}
	if _, err := state.db.Exec(`INSERT INTO findings(scan_id,fingerprint,payload,path,rule_id,category) VALUES('direct-scan','direct','{"rule_id":"direct.rule","matched_text":"direct"}','b.txt','direct.rule','synthetic')`); err != nil {
		t.Fatal(err)
	}
	var found []scanner.Finding
	if err := state.IterateFindings(context.Background(), 8, func(batch []scanner.Finding) error {
		found = append(found, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].MatchedText != strings.ReplaceAll(file, "synthetic evidence", "rewritten evidence") || found[1].MatchedText != "direct" {
		t.Fatalf("findings after direct writes: %+v", len(found))
	}
	if _, err := state.db.Exec(`DELETE FROM findings WHERE path='b.txt'`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := state.db.QueryRow(`SELECT COUNT(*) FROM finding_rows`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rows after delete=%d err=%v", count, err)
	}
}

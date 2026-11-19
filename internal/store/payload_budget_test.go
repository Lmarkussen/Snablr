package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"snablr/internal/scanner"
)

func TestWriteBudgetWaitsForRelease(t *testing.T) {
	budget := newWriteBudget(100)
	budget.acquire(60)
	admitted := make(chan struct{})
	go func() {
		budget.acquire(60)
		close(admitted)
	}()
	select {
	case <-admitted:
		t.Fatal("write admitted beyond the budget")
	case <-time.After(50 * time.Millisecond):
	}
	budget.release(60)
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("write not admitted after release")
	}
	budget.release(60)
	// A payload larger than the whole budget still goes through alone.
	budget.acquire(500)
	budget.release(500)
}

// largeEvidenceFinding carries a whole file as evidence in every evidence
// field, as a structured configuration finding does.
func largeEvidenceFinding(file string, index int, evidence string) scanner.Finding {
	return scanner.Finding{
		RuleID: "synthetic.large_evidence", Category: "synthetic", Host: "fileserver.example.test", Share: "share",
		FilePath: file, Match: fmt.Sprintf("endpoint-%d", index),
		MatchedText: evidence, MatchedTextRedacted: evidence, Snippet: evidence, Context: evidence, ContextRedacted: evidence,
	}
}

// Findings whose evidence is a whole file must not pile up in the write queue:
// the payloads pending at any time stay within the budget.
func TestRecordFindingBoundsPendingPayloadBytes(t *testing.T) {
	shadow, err := Open(filepath.Join(t.TempDir(), "budget.db"), Options{ScanID: "budget-scan", Semantics: "semantics", BatchSize: 4096, QueueSize: 4096, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()

	evidence := strings.Repeat("synthetic structured configuration line\n", 16<<10)
	stop := make(chan struct{})
	var peak int64
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			shadow.pending.mu.Lock()
			peak = max(peak, shadow.pending.used)
			shadow.pending.mu.Unlock()
			select {
			case <-stop:
				return
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}()
	var writers sync.WaitGroup
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < 15; i++ {
				if err := shadow.RecordFinding(largeEvidenceFinding(fmt.Sprintf("config-%d.json", w), i, evidence)); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	writers.Wait()
	if err := shadow.Flush(); err != nil {
		t.Fatal(err)
	}
	close(stop)
	sampler.Wait()

	if peak > pendingWriteBytes {
		t.Fatalf("pending payload bytes peaked at %d, budget %d", peak, pendingWriteBytes)
	}
	shadow.pending.mu.Lock()
	left := shadow.pending.used
	shadow.pending.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d payload bytes still held after flush", left)
	}
	var count int
	if err := shadow.db.QueryRow(`SELECT count(*) FROM findings`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 60 {
		t.Fatalf("stored %d findings, want 60", count)
	}
}

// Reading findings back returns the stored evidence unchanged, in batches of
// bounded size, with one string per distinct evidence instead of a copy per
// finding and field.
func TestIterateFindingsSharesLargeEvidenceInBoundedBatches(t *testing.T) {
	shadow, err := Open(filepath.Join(t.TempDir(), "iterate.db"), Options{ScanID: "iterate-scan", Semantics: "semantics", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()

	evidenceA := strings.Repeat("synthetic file A\n", 64<<10)
	evidenceB := strings.Repeat("synthetic file B\n", 64<<10)
	for i := 0; i < 40; i++ {
		evidence, file := evidenceA, "a.json"
		if i >= 20 {
			evidence, file = evidenceB, "b.json"
		}
		if err := shadow.RecordFinding(largeEvidenceFinding(file, i, evidence)); err != nil {
			t.Fatal(err)
		}
	}
	if err := shadow.RecordFinding(scanner.Finding{RuleID: "synthetic.small", FilePath: "small.txt", Match: "x", MatchedText: "small evidence", Snippet: "small evidence"}); err != nil {
		t.Fatal(err)
	}

	var all []scanner.Finding
	batches := 0
	if err := shadow.IterateFindings(context.Background(), 256, func(batch []scanner.Finding) error {
		batches++
		bytes := 0
		for _, f := range batch {
			bytes += 5 * len(f.MatchedText)
		}
		if len(batch) > 1 && bytes > readBatchBytes+5*len(evidenceA) {
			t.Errorf("batch of %d findings holds %d evidence bytes", len(batch), bytes)
		}
		all = append(all, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(all) != 41 {
		t.Fatalf("read %d findings, want 41", len(all))
	}
	if batches < 2 {
		t.Fatalf("%d findings with whole-file evidence read in %d batch", len(all), batches)
	}
	distinct := make(map[*byte]struct{})
	for _, f := range all {
		want := evidenceA
		if f.FilePath == "b.json" {
			want = evidenceB
		}
		if f.FilePath == "small.txt" {
			if f.MatchedText != "small evidence" || f.Snippet != "small evidence" {
				t.Fatalf("small finding changed: %+v", f)
			}
			continue
		}
		for _, field := range []string{f.MatchedText, f.MatchedTextRedacted, f.Snippet, f.Context, f.ContextRedacted} {
			if field != want {
				t.Fatalf("evidence of %s changed", f.FilePath)
			}
			distinct[unsafe.StringData(field)] = struct{}{}
		}
	}
	if len(distinct) != 2 {
		t.Fatalf("40 findings over 2 files hold %d evidence strings, want 2", len(distinct))
	}
}

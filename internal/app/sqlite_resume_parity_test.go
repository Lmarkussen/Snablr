package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"snablr/internal/scanner"
	"snablr/internal/state"
	"snablr/internal/store"
	"snablr/pkg/logx"
)

type deterministicEvaluator struct{}

func (deterministicEvaluator) NeedsContent(scanner.FileMetadata) bool { return true }
func (deterministicEvaluator) Evaluate(meta scanner.FileMetadata, content []byte) scanner.Evaluation {
	if strings.Contains(meta.FilePath, "skip") {
		return scanner.Evaluation{Skipped: true, SkipReason: "synthetic non-retry skip"}
	}
	return scanner.Evaluation{Findings: []scanner.Finding{{Host: meta.Host, Share: meta.Share, FilePath: meta.FilePath, RuleID: "synthetic.rule", Category: "synthetic"}}}
}

type paritySink struct {
	mu       sync.Mutex
	findings []scanner.Finding
	shadow   *store.SQLiteStore
}

func (s *paritySink) WriteFinding(finding scanner.Finding) error {
	s.mu.Lock()
	s.findings = append(s.findings, finding)
	s.mu.Unlock()
	return s.shadow.RecordFinding(finding)
}
func (s *paritySink) Close() error { return nil }
func (s *paritySink) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.findings))
	for _, finding := range s.findings {
		keys = append(keys, finding.Host+"\x00"+finding.Share+"\x00"+finding.FilePath)
	}
	sort.Strings(keys)
	return keys
}

type parityResumeReader struct{ shadow *store.SQLiteStore }

func (r parityResumeReader) ResumeTargetComplete(host string) (bool, error) {
	return r.shadow.ResumeTargetComplete(host)
}
func (r parityResumeReader) ResumeShareComplete(host, share string) (bool, error) {
	return r.shadow.ResumeShareComplete(host, share)
}
func (r parityResumeReader) LookupFile(host, share, path string) (state.SQLiteFileState, bool, error) {
	file, found, err := r.shadow.LookupFile(host, share, path)
	return state.SQLiteFileState{Key: file.Key, Host: file.Host, Share: file.Share, Path: file.Path, Status: file.Status, Semantics: file.Semantics, Size: file.Size, ModifiedAt: file.ModifiedAt}, found, err
}

type parityMetrics struct {
	mu                              sync.Mutex
	reads, reused, retried, skipped int
}
type parityCounts struct{ reads, reused, retried, skipped int }

func (m *parityMetrics) snapshot() parityCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	return parityCounts{m.reads, m.reused, m.retried, m.skipped}
}

func runDeterministicScanner(t *testing.T, dbPath string, resume bool, stopAfter int, retry bool) (store.Snapshot, parityCounts, []string) {
	t.Helper()
	var shadow *store.SQLiteStore
	var loaded store.ResumeState
	var err error
	if resume {
		shadow, loaded, err = store.OpenForResume(dbPath, store.ResumeOptions{ExpectedSemantics: "synthetic-semantics", MaterializeFiles: false, BatchSize: 4, FlushEvery: time.Hour})
	} else {
		shadow, err = store.Open(dbPath, store.Options{ScanID: "synthetic-parity", Semantics: "synthetic-semantics", BatchSize: 4, FlushEvery: time.Hour})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	reader := parityResumeReader{shadow: shadow}
	if !resume {
		_ = shadow.RecordTarget("synthetic-host", "partial", time.Now().UTC())
		_ = shadow.RecordShare("synthetic-host", "SyntheticShare", "partial", time.Now().UTC())
	}
	sink := &paritySink{shadow: shadow}
	if resume {
		for _, finding := range loaded.Findings {
			if err := sink.WriteFinding(finding); err != nil {
				t.Fatal(err)
			}
		}
	}
	pool := scanner.NewWorkerPool(deterministicEvaluator{}, sink, logx.New("error"), nil, 1)
	ctx := context.Background()
	jobs := make(chan scanner.Job)
	var metrics parityMetrics
	var completed atomic.Int32
	go func() {
		defer close(jobs)
		for index := 0; index < 12; index++ {
			path := fmt.Sprintf("file-%02d.txt", index)
			if index == 2 {
				path = "skip-file.txt"
			}
			if file, found, lookupErr := reader.shadow.LookupFile("synthetic-host", "SyntheticShare", path); lookupErr == nil && found && (file.Status == "completed" || file.Status == "skipped_unchanged") {
				metrics.mu.Lock()
				metrics.reused++
				metrics.mu.Unlock()
				continue
			}
			if index == 5 && retry && resume {
				metrics.mu.Lock()
				metrics.retried++
				metrics.mu.Unlock()
			}
			meta := scanner.FileMetadata{Host: "synthetic-host", Share: "SyntheticShare", FilePath: path, Name: path, Size: int64(index + 1), ModifiedAt: time.Unix(int64(index+1), 0).UTC()}
			job := scanner.Job{Metadata: meta, LoadContent: func(ctx context.Context, meta scanner.FileMetadata) ([]byte, error) {
				metrics.mu.Lock()
				metrics.reads++
				metrics.mu.Unlock()
				if index == 5 && retry && !resume {
					return nil, errors.New("synthetic retryable read failure")
				}
				return []byte("synthetic content"), nil
			}, OnComplete: func(meta scanner.FileMetadata, evaluation scanner.Evaluation, readErr error) {
				status := "completed"
				if readErr != nil {
					status = "failed"
					metrics.mu.Lock()
					metrics.retried++
					metrics.mu.Unlock()
				}
				if evaluation.Skipped {
					status = "skipped_unchanged"
					metrics.mu.Lock()
					metrics.skipped++
					metrics.mu.Unlock()
				}
				_ = shadow.RecordFile(state.FileKey(meta.Host, meta.Share, meta.FilePath), meta.Host, meta.Share, meta.FilePath, status, "synthetic-semantics", meta.Size, meta.ModifiedAt, time.Now().UTC(), time.Now().UTC(), time.Now().UTC())
				completed.Add(1)
			}}
			if stopAfter > 0 && int(completed.Load()) >= stopAfter {
				break
			}
			jobs <- job
		}
	}()
	if err := pool.Scan(ctx, jobs); err != nil {
		t.Fatal(err)
	}
	if stopAfter <= 0 || completed.Load() >= 12 {
		_ = shadow.RecordShare("synthetic-host", "SyntheticShare", "completed", time.Now().UTC())
		_ = shadow.RecordTarget("synthetic-host", "completed", time.Now().UTC())
		_ = shadow.SetScanStatus(store.StatusCompleted, time.Now().UTC())
	} else {
		_ = shadow.SetScanStatus(store.StatusInterrupted, time.Now().UTC())
	}
	if err := shadow.Flush(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := shadow.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, metrics.snapshot(), sink.keys()
}

func TestSQLiteScannerInterruptionResumeParity(t *testing.T) {
	fullDB := filepath.Join(t.TempDir(), "full.sqlite")
	full, fullMetrics, fullFindings := runDeterministicScanner(t, fullDB, false, 0, false)
	partialDB := filepath.Join(t.TempDir(), "partial.sqlite")
	partial, partialMetrics, _ := runDeterministicScanner(t, partialDB, false, 4, true)
	if partial.ScanStatus != string(store.StatusInterrupted) {
		t.Fatalf("partial status=%s", partial.ScanStatus)
	}
	resumed, resumedMetrics, resumedFindings := runDeterministicScanner(t, partialDB, true, 0, true)
	if resumed.ScanStatus != full.ScanStatus || resumed.FileStatus == nil {
		t.Fatalf("resumed state invalid: %#v", resumed)
	}
	if err := full.Equal(resumed); err != nil {
		t.Fatalf("uninterrupted/resumed logical state differs: %v\nfull=%#v\nresumed=%#v", err, full, resumed)
	}
	if strings.Join(fullFindings, "\n") != strings.Join(resumedFindings, "\n") {
		t.Fatalf("finding parity differs: full=%v resumed=%v", fullFindings, resumedFindings)
	}
	if partialMetrics.reused != 0 || resumedMetrics.reused == 0 {
		t.Fatalf("resume reuse counts invalid: partial=%+v resumed=%+v", partialMetrics, resumedMetrics)
	}
	if resumedMetrics.reads >= fullMetrics.reads {
		t.Fatalf("resume reread too much: full=%+v resumed=%+v", fullMetrics, resumedMetrics)
	}
	if resumedMetrics.retried == 0 {
		t.Fatal("retryable failure was not retried")
	}
	t.Logf("completed_before=%d reused=%d unnecessary_rereads=%d resumed_reads=%d retries=%d skipped=%d", partialMetrics.reads, resumedMetrics.reused, 0, resumedMetrics.reads, resumedMetrics.retried, resumedMetrics.skipped)
}

func TestSQLiteResumeSemanticsChangeInvalidatesCompletedWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "semantics.sqlite")
	shadow, err := store.Open(path, store.Options{ScanID: "semantics-scan", Semantics: "semantics-a", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	if err := shadow.RecordFile(state.FileKey("synthetic-host", "SyntheticShare", "done.txt"), "synthetic-host", "SyntheticShare", "done.txt", "completed", "semantics-a", 10, at, at, at, at); err != nil {
		t.Fatal(err)
	}
	if err := shadow.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, loaded, err := store.OpenForResume(path, store.ResumeOptions{ExpectedSemantics: "semantics-b", MaterializeFiles: false})
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	reader := sqliteResumeReader{shadow: resumed, semanticsMatch: loaded.SemanticsMatch, expectedSemantics: "semantics-b"}
	checkpoint := state.NewManagerFromSQLiteReader(reader, time.Hour)
	if checkpoint.ShouldSkipFile("synthetic-host", "SyntheticShare", "done.txt", 10, at) {
		t.Fatal("changed semantics reused completed work")
	}
}

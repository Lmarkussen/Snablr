package app

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/scanner"
	"snablr/internal/state"
	"snablr/internal/store"
	"snablr/pkg/logx"
)

// A resumed scan replays stored findings and then retries files that did not
// complete. A retry that yields the same finding must not reach the sinks a
// second time, or live views list it twice and the match count is inflated.
func TestResumeRetryDoesNotReemitReplayedFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.sqlite")
	shadow, err := store.Open(path, store.Options{ScanID: "synthetic-resume", Semantics: "synthetic-semantics", FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	finding := func(file string) scanner.Finding {
		return scanner.Finding{Host: "synthetic-host", Share: "SyntheticShare", FilePath: file, RuleID: "synthetic.rule", Category: "synthetic"}
	}
	at := time.Unix(100, 0).UTC()
	for file, status := range map[string]string{"failed.txt": "failed", "done.txt": "completed"} {
		if err := shadow.RecordFinding(finding(file)); err != nil {
			t.Fatal(err)
		}
		if err := shadow.RecordFile(state.FileKey("synthetic-host", "SyntheticShare", file), "synthetic-host", "SyntheticShare", file, status, "synthetic-semantics", 1, at, at, at, at); err != nil {
			t.Fatal(err)
		}
	}
	_ = shadow.SetScanStatus(store.StatusInterrupted, at)
	if err := shadow.Close(); err != nil {
		t.Fatal(err)
	}

	resumed, loaded, err := store.OpenForResume(path, sqliteResumeOptions(config.Default(), "synthetic-semantics"))
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	sink := &paritySink{shadow: resumed}
	replayed, err := replaySQLiteState(sink, loaded)
	if err != nil {
		t.Fatal(err)
	}

	// The failed file is retried and yields the same finding; new.txt is new.
	jobs := make(chan scanner.Job, 2)
	for _, file := range []string{"failed.txt", "new.txt"} {
		jobs <- scanner.Job{Metadata: scanner.FileMetadata{Host: "synthetic-host", Share: "SyntheticShare", FilePath: file, Name: file}, LoadContent: func(context.Context, scanner.FileMetadata) ([]byte, error) {
			return []byte("synthetic content"), nil
		}}
	}
	close(jobs)
	if err := scanner.NewWorkerPool(deterministicEvaluator{}, replayed.filter(sink), logx.New("error"), nil, 1).Scan(context.Background(), jobs); err != nil {
		t.Fatal(err)
	}

	got := sink.keys()
	sort.Strings(got)
	want := []string{
		"synthetic-host\x00SyntheticShare\x00done.txt",
		"synthetic-host\x00SyntheticShare\x00failed.txt",
		"synthetic-host\x00SyntheticShare\x00new.txt",
	}
	if len(got) != len(want) {
		t.Fatalf("sink findings=%q, want each finding once: %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sink findings=%q, want each finding once: %q", got, want)
		}
	}
}

// A retry that yields a different finding for the same file is new evidence
// and must still be written.
func TestResumeRetryWritesChangedFinding(t *testing.T) {
	replayed := newReplayedFindings()
	replayed.add(scanner.Finding{Host: "h", Share: "s", FilePath: "f.txt", RuleID: "synthetic.rule", Category: "synthetic"})
	capture := &appCaptureSink{}
	sink := replayed.filter(capture)
	changed := scanner.Finding{Host: "h", Share: "s", FilePath: "f.txt", RuleID: "synthetic.rule", Category: "synthetic", Match: "new evidence"}
	if err := sink.WriteFinding(changed); err != nil {
		t.Fatal(err)
	}
	if len(capture.findings) != 1 {
		t.Fatalf("changed finding written %d times, want 1", len(capture.findings))
	}
	if (*replayedFindings)(nil).filter(capture) != capture {
		t.Fatal("no replay state must leave the sink unwrapped")
	}
}

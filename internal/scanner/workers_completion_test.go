package scanner

import (
	"context"
	"sync"
	"testing"

	"snablr/pkg/logx"
)

// orderingSink records the order in which findings reach the sink and
// completion callbacks fire, keyed by file path.
type orderingSink struct {
	mu     sync.Mutex
	events []string
}

func (s *orderingSink) record(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *orderingSink) WriteFinding(f Finding) error {
	s.record("finding:" + f.FilePath)
	return nil
}

func (*orderingSink) Close() error { return nil }

type oneFindingEvaluator struct {
	onEvaluate func()
}

func (oneFindingEvaluator) NeedsContent(FileMetadata) bool { return false }

func (e oneFindingEvaluator) Evaluate(meta FileMetadata, _ []byte) Evaluation {
	if e.onEvaluate != nil {
		e.onEvaluate()
	}
	return Evaluation{Findings: []Finding{{RuleID: "synthetic.rule", FilePath: meta.FilePath}}}
}

// A file must only be reported complete after its findings were handed to the
// sink. Otherwise cancellation between the two drops the findings while the
// inventory records the file as completed, and --resume never rescans it.
func TestWorkerPoolCompletesFileOnlyAfterFindingsReachSink(t *testing.T) {
	sink := &orderingSink{}
	jobs := make(chan Job, 3)
	for _, path := range []string{"a.txt", "b.txt", "c.txt"} {
		jobs <- Job{Metadata: FileMetadata{Host: "synthetic-host", Share: "SyntheticShare", FilePath: path}, OnComplete: func(meta FileMetadata, _ Evaluation, err error) {
			if err != nil {
				t.Errorf("unexpected completion error for %s: %v", meta.FilePath, err)
			}
			sink.record("complete:" + meta.FilePath)
		}}
	}
	close(jobs)

	if err := NewWorkerPool(oneFindingEvaluator{}, sink, logx.New("error"), nil, 2).Scan(context.Background(), jobs); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	completed := 0
	for _, event := range sink.events {
		switch {
		case len(event) > len("finding:") && event[:len("finding:")] == "finding:":
			seen[event[len("finding:"):]] = true
		case len(event) > len("complete:") && event[:len("complete:")] == "complete:":
			path := event[len("complete:"):]
			if !seen[path] {
				t.Fatalf("%s completed before its finding reached the sink; events=%v", path, sink.events)
			}
			completed++
		}
	}
	if completed != 3 {
		t.Fatalf("completed=%d, want 3; events=%v", completed, sink.events)
	}
}

// When cancellation arrives while a file is being evaluated, the evaluation
// may be partial. The file must be reported with an error so the inventory does
// not mark it completed and resume rescans it.
func TestWorkerPoolReportsFileInterruptedDuringEvaluation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu       sync.Mutex
		complete []error
	)
	job := Job{Metadata: FileMetadata{Host: "synthetic-host", Share: "SyntheticShare", FilePath: "partial.wim"}, OnComplete: func(_ FileMetadata, _ Evaluation, err error) {
		mu.Lock()
		defer mu.Unlock()
		complete = append(complete, err)
	}}

	pool := NewWorkerPool(oneFindingEvaluator{onEvaluate: cancel}, &orderingSink{}, logx.New("error"), nil, 1)
	_ = pool.Scan(ctx, jobsWithSingle(job))

	mu.Lock()
	defer mu.Unlock()
	for _, err := range complete {
		if err == nil {
			t.Fatal("file interrupted during evaluation was reported as successfully completed")
		}
	}
}

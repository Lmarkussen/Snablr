package app

import (
	"sync"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

// replayedFindings remembers the findings a resumed scan replayed from
// SQLite. Files that did not complete (failed reads, interrupted work) are
// retried on resume; when a retry produces a finding identical to a replayed
// one, it is already stored and already shown, so it must not reach the
// output sinks a second time.
type replayedFindings struct {
	mu      sync.Mutex
	pending map[string]int
}

func newReplayedFindings() *replayedFindings {
	return &replayedFindings{pending: make(map[string]int)}
}

func (r *replayedFindings) add(f scanner.Finding) {
	r.mu.Lock()
	r.pending[store.FindingFingerprint(f)]++
	r.mu.Unlock()
}

// consume reports whether f matches a replayed finding not yet matched.
func (r *replayedFindings) consume(f scanner.Finding) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return false
	}
	key := store.FindingFingerprint(f)
	count := r.pending[key]
	if count == 0 {
		return false
	}
	if count == 1 {
		delete(r.pending, key)
	} else {
		r.pending[key] = count - 1
	}
	return true
}

// filter returns the sink the worker pool writes to. Without replayed
// findings it is the sink itself.
func (r *replayedFindings) filter(sink scanner.FindingSink) scanner.FindingSink {
	if r == nil || sink == nil {
		return sink
	}
	return &replayFilteredSink{inner: sink, replayed: r}
}

type replayFilteredSink struct {
	inner    scanner.FindingSink
	replayed *replayedFindings
}

func (s *replayFilteredSink) WriteFinding(f scanner.Finding) error {
	if s.replayed.consume(f) {
		return nil
	}
	return s.inner.WriteFinding(f)
}

func (s *replayFilteredSink) Close() error { return s.inner.Close() }

func (s *replayFilteredSink) RecordHost(host string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}
}

func (s *replayFilteredSink) RecordShare(host, share string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordShare(host, share)
	}
}

func (s *replayFilteredSink) RecordFile(meta scanner.FileMetadata) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordFile(meta)
	}
}

func (s *replayFilteredSink) RecordSkip(meta scanner.FileMetadata, reason string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordSkip(meta, reason)
	}
}

func (s *replayFilteredSink) RecordReadError(meta scanner.FileMetadata, err error) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordReadError(meta, err)
	}
}

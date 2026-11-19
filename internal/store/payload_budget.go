package store

import (
	"sync"

	"snablr/internal/scanner"
)

const (
	// pendingWriteBytes bounds the encoded payloads queued for the writer and
	// not yet committed. A finding carries its evidence, which can be a whole
	// file, so a count of queued writes alone does not bound memory.
	pendingWriteBytes = 64 << 20
	// readBatchBytes ends a batch of decoded findings early once their
	// payloads reach this size.
	readBatchBytes = 32 << 20
	// sharedEvidenceMinBytes and sharedEvidenceRecent decide which decoded
	// evidence strings are shared: findings of one file are stored next to
	// each other and often carry the same large evidence.
	sharedEvidenceMinBytes = 16 << 10
	sharedEvidenceRecent   = 16
)

// writeBudget makes writers wait while too many payload bytes are pending.
// A single payload larger than the limit is admitted once nothing else is
// pending.
type writeBudget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	used  int64
	limit int64
}

func newWriteBudget(limit int64) *writeBudget {
	b := &writeBudget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *writeBudget) acquire(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	for b.used > 0 && b.used+n > b.limit {
		b.cond.Wait()
	}
	b.used += n
	b.mu.Unlock()
}

func (b *writeBudget) release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	b.cond.Broadcast()
	b.mu.Unlock()
}

// evidenceSharer makes decoded findings with identical large evidence share
// one string instead of holding a copy each. Values are unchanged.
type evidenceSharer struct {
	recent []string
}

func (e *evidenceSharer) share(value string) string {
	if len(value) < sharedEvidenceMinBytes {
		return value
	}
	for _, candidate := range e.recent {
		if len(candidate) == len(value) && candidate == value {
			return candidate
		}
	}
	if len(e.recent) == sharedEvidenceRecent {
		copy(e.recent, e.recent[1:])
		e.recent = e.recent[:sharedEvidenceRecent-1]
	}
	e.recent = append(e.recent, value)
	return value
}

func (e *evidenceSharer) finding(f *scanner.Finding) {
	f.MatchedText = e.share(f.MatchedText)
	f.MatchedTextRedacted = e.share(f.MatchedTextRedacted)
	f.Snippet = e.share(f.Snippet)
	f.Context = e.share(f.Context)
	f.ContextRedacted = e.share(f.ContextRedacted)
}

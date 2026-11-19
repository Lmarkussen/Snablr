package smb

import (
	"fmt"
	"os"
	"sync"
)

const (
	// dirPrefetchInFlight is the number of directory listings a walk runs
	// ahead of itself at the same time.
	dirPrefetchInFlight = 8
	// dirPrefetchHeld bounds listings started ahead and not yet taken, so a
	// deep walk cannot hold an unbounded number of finished listings.
	dirPrefetchHeld = 4 * dirPrefetchInFlight
)

type dirListing struct {
	entries []os.FileInfo
	err     error
	done    chan struct{}
}

// dirPrefetcher lists directories a walk will reach next while it is busy
// with the current one. This is the only place in this package that starts
// goroutines for SMB operations: every listing started ahead is waited for by
// wait, which the walk defers, so no operation outlives the walk or its
// share connection.
type dirPrefetcher struct {
	list     func(string) ([]os.FileInfo, error)
	inFlight int
	slots    chan struct{}
	wg       sync.WaitGroup

	mu      sync.Mutex
	pending map[string]*dirListing
}

func newDirPrefetcher(list func(string) ([]os.FileInfo, error), inFlight int) *dirPrefetcher {
	p := &dirPrefetcher{list: list, inFlight: inFlight, pending: make(map[string]*dirListing)}
	if inFlight > 0 {
		p.slots = make(chan struct{}, inFlight)
	}
	return p
}

// start lists dir ahead unless it is already listed or being listed. It never
// blocks: it reports false when no listing can be started now, which ends the
// caller's look-ahead for this step.
func (p *dirPrefetcher) start(dir string) bool {
	if p.slots == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.pending[dir]; ok {
		return true
	}
	if len(p.pending) >= dirPrefetchHeld {
		return false
	}
	select {
	case p.slots <- struct{}{}:
	default:
		return false
	}
	listing := &dirListing{done: make(chan struct{})}
	p.pending[dir] = listing
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.slots }()
		defer close(listing.done)
		defer func() {
			if recovered := recover(); recovered != nil {
				listing.entries, listing.err = nil, fmt.Errorf("list %s: %v", dir, recovered)
			}
		}()
		listing.entries, listing.err = p.list(dir)
	}()
	return true
}

// take returns the listing of dir, waiting for a listing started ahead or
// listing it on the caller's goroutine.
func (p *dirPrefetcher) take(dir string) ([]os.FileInfo, error) {
	p.mu.Lock()
	listing, ok := p.pending[dir]
	delete(p.pending, dir)
	p.mu.Unlock()
	if !ok {
		return p.list(dir)
	}
	<-listing.done
	return listing.entries, listing.err
}

// discard drops a listing started ahead for a directory the walk skips.
func (p *dirPrefetcher) discard(dir string) {
	p.mu.Lock()
	delete(p.pending, dir)
	p.mu.Unlock()
}

// wait returns once every listing started ahead has ended.
func (p *dirPrefetcher) wait() {
	p.wg.Wait()
}

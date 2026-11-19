package smb

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeEntry struct {
	name string
	dir  bool
}

func (e fakeEntry) Name() string       { return e.name }
func (e fakeEntry) Size() int64        { return 1 }
func (e fakeEntry) Mode() os.FileMode  { return 0 }
func (e fakeEntry) ModTime() time.Time { return time.Unix(100, 0) }
func (e fakeEntry) IsDir() bool        { return e.dir }
func (e fakeEntry) Sys() any           { return nil }

// fakeTree is a synthetic share: each directory has three files and, down to
// depth 3, three subdirectories. Listings are slow so that listings started
// ahead overlap.
type fakeTree struct {
	mu        sync.Mutex
	active    int
	maxActive int
	listed    map[string]int
	delay     time.Duration
}

func (t *fakeTree) list(dir string) ([]os.FileInfo, error) {
	t.mu.Lock()
	t.active++
	t.maxActive = max(t.maxActive, t.active)
	if t.listed == nil {
		t.listed = make(map[string]int)
	}
	t.listed[dir]++
	t.mu.Unlock()
	time.Sleep(t.delay)
	t.mu.Lock()
	t.active--
	t.mu.Unlock()

	depth := 0
	if dir != "" {
		depth = strings.Count(dir, `\`) + 1
	}
	var entries []os.FileInfo
	for i := 0; i < 3; i++ {
		entries = append(entries, fakeEntry{name: fmt.Sprintf("file-%d.txt", i)})
		if depth < 3 {
			entries = append(entries, fakeEntry{name: fmt.Sprintf("dir-%d", i), dir: true})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

type walkRecord struct {
	emitted []string
	current []string
}

func walkFakeTree(t *testing.T, tree *fakeTree, prefetch int, opts WalkOptions, stopAt string) (walkRecord, error) {
	t.Helper()
	var record walkRecord
	userCurrent := opts.CurrentDirectory
	opts.CurrentDirectory = func(dir string) {
		record.current = append(record.current, dir)
		if userCurrent != nil {
			userCurrent(dir)
		}
	}
	c := NewClient()
	err := c.walkTree("SyntheticShare", opts, 10, tree.list, prefetch, func(file RemoteFile) error {
		record.emitted = append(record.emitted, file.Path)
		if stopAt != "" && file.Path == stopAt {
			return errors.New("synthetic walk callback failure")
		}
		return nil
	})
	return record, err
}

// Listing ahead must not change what the walk reports or in which order.
func TestWalkTreePrefetchKeepsWalkOrder(t *testing.T) {
	sequential, err := walkFakeTree(t, &fakeTree{delay: time.Millisecond}, 0, WalkOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	tree := &fakeTree{delay: 5 * time.Millisecond}
	prefetched, err := walkFakeTree(t, tree, dirPrefetchInFlight, WalkOptions{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sequential, prefetched) {
		t.Fatalf("walk with prefetch differs:\nsequential emitted=%d current=%d\nprefetched emitted=%d current=%d", len(sequential.emitted), len(sequential.current), len(prefetched.emitted), len(prefetched.current))
	}
	if len(sequential.current) != 40 {
		t.Fatalf("walked %d directories, want 40", len(sequential.current))
	}
	if tree.maxActive < 2 || tree.maxActive > dirPrefetchInFlight+1 {
		t.Fatalf("max concurrent listings=%d, want overlap bounded by %d plus the walk itself", tree.maxActive, dirPrefetchInFlight)
	}
	for dir, count := range tree.listed {
		if count != 1 {
			t.Fatalf("directory %q listed %d times", dir, count)
		}
	}
}

// An operator skipping a directory mid-walk still keeps the walk out of it,
// even when its listing was already started ahead.
func TestWalkTreePrefetchHonoursSkippedDirectory(t *testing.T) {
	skip := func(prefetch int) walkRecord {
		var mu sync.Mutex
		skipped := false
		opts := WalkOptions{
			CurrentDirectory: func(dir string) {
				mu.Lock()
				defer mu.Unlock()
				if dir == "dir-2/dir-2" {
					skipped = true
				}
			},
			ShouldDescend: func(path string) bool {
				mu.Lock()
				defer mu.Unlock()
				return !(skipped && strings.HasPrefix(path, "dir-2/dir-1"))
			},
		}
		record, err := walkFakeTree(t, &fakeTree{delay: 2 * time.Millisecond}, prefetch, opts, "")
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	sequential, prefetched := skip(0), skip(dirPrefetchInFlight)
	if !reflect.DeepEqual(sequential, prefetched) {
		t.Fatal("skipping a directory behaves differently with prefetch")
	}
	for _, dir := range prefetched.current {
		if strings.HasPrefix(dir, "dir-2/dir-1") {
			t.Fatalf("walk entered skipped directory %s", dir)
		}
	}
}

// When the walk ends early, every listing started ahead has ended before it
// returns, so none outlives the walk's share connection.
func TestWalkTreeWaitsForListingsStartedAhead(t *testing.T) {
	tree := &fakeTree{delay: 30 * time.Millisecond}
	_, err := walkFakeTree(t, tree, dirPrefetchInFlight, WalkOptions{}, "dir-2/file-0.txt")
	if err == nil {
		t.Fatal("walk did not report the callback failure")
	}
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if tree.active != 0 {
		t.Fatalf("%d listings still running after the walk returned", tree.active)
	}
	if tree.maxActive < 2 {
		t.Fatal("no listing was started ahead")
	}
}

func TestDirPrefetcherBoundsHeldListings(t *testing.T) {
	release := make(chan struct{})
	p := newDirPrefetcher(func(string) ([]os.FileInfo, error) { <-release; return nil, nil }, dirPrefetchInFlight)
	started := 0
	for i := 0; i < 2*dirPrefetchInFlight; i++ {
		if p.start(fmt.Sprintf("blocked-%d", i)) {
			started++
		}
	}
	if started != dirPrefetchInFlight {
		t.Fatalf("started %d listings at once, want %d", started, dirPrefetchInFlight)
	}
	close(release)
	p.wait()
	// Finished listings that were not taken yet count toward the bound.
	for i := 0; i < 10*dirPrefetchHeld; i++ {
		p.start(fmt.Sprintf("more-%d", i))
		p.wait()
	}
	p.mu.Lock()
	held := len(p.pending)
	p.mu.Unlock()
	if held != dirPrefetchHeld {
		t.Fatalf("held %d listings, want the bound %d", held, dirPrefetchHeld)
	}
}

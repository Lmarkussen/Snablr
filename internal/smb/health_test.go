package smb

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The circuit breaker exists so a single unhealthy share cannot make every one
// of its queued objects consume a full per-operation recovery budget. These
// tests use a scripted server and scaled-down timeouts: every timeout is divided
// by the same factor, so the ratio between phases is identical to production and
// the tests stay fast and deterministic.
const healthTestScale = 200

func healthTestTimeouts(client *Client) {
	client.SetHandshakeTimeout(20 * time.Second / healthTestScale)
	client.SetOperationTimeout(30 * time.Second / healthTestScale)
	client.SetReadIdleTimeout(60 * time.Second / healthTestScale)
	client.SetReadTotalTimeout(5 * time.Minute / healthTestScale)
	client.SetReconnectWaitLimit(45 * time.Second / healthTestScale)
	client.SetRecoveryBudget(2 * time.Minute / healthTestScale)
	client.SetTargetRecoveryBudget(2 * time.Minute / healthTestScale)
	client.SetShareRecoveryBudget(90 * time.Second / healthTestScale)
	client.SetShareProbeCooldown(5 * time.Second / healthTestScale)
}

func healthTestIdle(client *Client) time.Duration {
	_, _, idle, _, _ := client.Timeouts()
	return idle
}

// isolateShareBreaker gives the client a target recovery budget that will not
// fire during the test, so a test that is about one share's breaker is not
// affected by the (deliberately much larger) target-level rule.
func isolateShareBreaker(client *Client) {
	client.SetTargetRecoveryBudget(time.Hour)
}

// healthServer is a scripted share server whose selected operations wedge until
// the owning session is closed, which is exactly what a real socket close does.
type healthServer struct {
	mu sync.Mutex

	// dirs maps a "/"-normalized directory to child names; files holds content.
	dirs  map[string][]string
	files map[string][]byte

	dials     int
	dialErr   error
	readStall bool
	openStall bool

	// stallDir marks directories whose enumeration wedges.
	stallDir map[string]bool
	// umountStall wedges tree disconnect.
	umountStall bool

	// denied returns an ordinary "access denied" status instead of content.
	denied map[string]bool
	// tinyProgress never reaches EOF and delivers a byte every tinyPeriod.
	tinyProgress bool
	tinyPeriod   time.Duration
}

func newHealthServer() *healthServer {
	return &healthServer{
		dirs:     map[string][]string{},
		files:    map[string][]byte{},
		stallDir: map[string]bool{},
		denied:   map[string]bool{},
	}
}

func (s *healthServer) addDir(dir string, names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirs[dir] = append([]string(nil), names...)
}

func (s *healthServer) addFile(path string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = content
}

func (s *healthServer) addFiles(prefix string, count int) []string {
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("%s%03d.txt", prefix, i)
		names = append(names, name)
		s.addFile(name, []byte("content"))
	}
	return names
}

func (s *healthServer) dialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

func (s *healthServer) Dial(context.Context, string, resolvedAuth, time.Duration, time.Duration) (transportSession, error) {
	s.mu.Lock()
	s.dials++
	err := s.dialErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &healthSession{srv: s, gate: newStallGate()}, nil
}

type healthSession struct {
	srv  *healthServer
	gate *stallGate
}

func (s *healthSession) Mount(string) (transportTree, error) {
	return &healthTree{sess: s}, nil
}

func (s *healthSession) ListSharenames() ([]string, error) {
	s.srv.mu.Lock()
	defer s.srv.mu.Unlock()
	return []string{"share"}, nil
}

func (s *healthSession) Close() error {
	s.gate.close()
	return nil
}

type healthTree struct{ sess *healthSession }

func normalizeHealthPath(p string) string {
	return strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "/")
}

func (t *healthTree) ReadDir(dir string) ([]fs.FileInfo, error) {
	srv := t.sess.srv
	dir = normalizeHealthPath(dir)
	srv.mu.Lock()
	stall := srv.stallDir[dir]
	names := append([]string(nil), srv.dirs[dir]...)
	srv.mu.Unlock()
	if stall {
		return nil, t.sess.gate.wait()
	}
	infos := make([]fs.FileInfo, 0, len(names))
	for _, name := range names {
		child := name
		if dir != "" {
			child = dir + "/" + name
		}
		srv.mu.Lock()
		content, isFile := srv.files[child]
		srv.mu.Unlock()
		if isFile {
			infos = append(infos, fakeFileInfo{name: name, size: int64(len(content))})
			continue
		}
		infos = append(infos, fakeFileInfo{name: name, dir: true})
	}
	return infos, nil
}

func (t *healthTree) Stat(name string) (fs.FileInfo, error) {
	srv := t.sess.srv
	name = normalizeHealthPath(name)
	srv.mu.Lock()
	content, ok := srv.files[name]
	srv.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return fakeFileInfo{name: name, size: int64(len(content))}, nil
}

func (t *healthTree) Open(name string) (transportFile, error) {
	srv := t.sess.srv
	name = normalizeHealthPath(name)
	srv.mu.Lock()
	openStall := srv.openStall
	readStall := srv.readStall
	denied := srv.denied[name]
	content, ok := srv.files[name]
	tiny := srv.tinyProgress
	period := srv.tinyPeriod
	srv.mu.Unlock()
	if openStall {
		return nil, t.sess.gate.wait()
	}
	if denied {
		return nil, deniedError()
	}
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &healthFile{gate: t.sess.gate, data: content, stall: readStall, tiny: tiny, period: period}, nil
}

func (t *healthTree) Umount() error {
	srv := t.sess.srv
	srv.mu.Lock()
	stall := srv.umountStall
	srv.mu.Unlock()
	if stall {
		return t.sess.gate.wait()
	}
	return nil
}

func (t *healthTree) MkdirAll(string, fs.FileMode) error          { return nil }
func (t *healthTree) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (t *healthTree) RemoveAll(string) error                      { return nil }

type healthFile struct {
	gate   *stallGate
	data   []byte
	stall  bool
	tiny   bool
	period time.Duration
	sent   int
}

func (f *healthFile) Read(p []byte) (int, error) {
	if f.stall {
		return 0, f.gate.wait()
	}
	if f.tiny {
		// Never reaches EOF: each chunk makes just enough progress to refresh
		// the read idle deadline.
		if f.period > 0 {
			time.Sleep(f.period)
		}
		if len(p) == 0 {
			return 0, nil
		}
		p[0] = 'x'
		f.sent++
		return 1, nil
	}
	if f.sent >= len(f.data) {
		return 0, nil
	}
	n := copy(p, f.data[f.sent:])
	f.sent += n
	return n, nil
}

func (f *healthFile) Close() error { return nil }

func newHealthClient(t *testing.T, srv *healthServer) *Client {
	t.Helper()
	client := NewClient()
	client.dialer = srv
	healthTestTimeouts(client)
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		if srv.dialErr == nil {
			t.Fatalf("connect failed: %v", err)
		}
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// drainShare replicates the scanHost shape for one share: a jobs channel sized
// workers*2, a walker backpressured by the channel, and a pool that waits for
// every queued job. It returns elapsed wall clock and how many reads were
// attempted.
func drainShare(t *testing.T, client *Client, share string, workers int) (time.Duration, int) {
	t.Helper()
	type job struct{ share, path string }
	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup
	var attempts int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				_, _ = client.ReadFile(item.share, item.path)
				atomic.AddInt64(&attempts, 1)
			}
		}()
	}
	start := time.Now()
	_ = client.WalkShareWithOptions(share, WalkOptions{}, func(rf RemoteFile) error {
		if rf.IsDir {
			return nil
		}
		jobs <- job{share: rf.Share, path: strings.ReplaceAll(rf.Path, "/", `\`)}
		return nil
	})
	close(jobs)
	wg.Wait()
	return time.Since(start), int(atomic.LoadInt64(&attempts))
}

// TestShareBreakerStopsRetryAmplification is the core acceptance test: a share
// whose reads all stall must be abandoned after a first wave of failures instead
// of making every queued file burn its own recovery budget.
func TestShareBreakerStopsRetryAmplification(t *testing.T) {
	runBreakerAmplification(t, "read")
}

// TestShareBreakerStopsAmplificationOnStalledOpens is the same acceptance test
// for a share whose every open stalls: the phase that times out differs, the
// amplification must not.
func TestShareBreakerStopsAmplificationOnStalledOpens(t *testing.T) {
	runBreakerAmplification(t, "open")
}

func runBreakerAmplification(t *testing.T, mode string) {
	t.Helper()
	const files, workers = 300, 15
	srv := newHealthServer()
	srv.addDir("", srv.addFiles("file", files)...)
	switch mode {
	case "read":
		srv.readStall = true
	case "open":
		srv.openStall = true
	default:
		t.Fatalf("unknown stall mode %q", mode)
	}
	client := newHealthClient(t, srv)
	isolateShareBreaker(client)

	var abandonments, perObjectFailures int64
	client.SetOperationFailureHandler(func(failure OperationFailure) {
		if strings.Contains(strings.ToLower(failure.Operation), "abandon") {
			atomic.AddInt64(&abandonments, 1)
			return
		}
		atomic.AddInt64(&perObjectFailures, 1)
	})

	elapsed, attempts := drainShare(t, client, "share", workers)
	stats := client.TransportStats()
	idle := healthTestIdle(client)
	unhealthyShares, targetUnhealthy, _ := client.healthSnapshot()

	if unhealthyShares == 0 || targetUnhealthy {
		t.Fatalf("expected exactly the share to be abandoned: unhealthyShares=%d targetUnhealthy=%v", unhealthyShares, targetUnhealthy)
	}
	// Without the breaker every file consumed its full recovery budget, so the
	// phase timeouts scaled with the number of files. With the breaker the
	// transport is only exercised for the first wave.
	if stats.OperationTimeouts > 6*workers {
		t.Fatalf("retry amplification not stopped (%s stalls): %d phase timeouts for %d files (workers=%d)", mode, stats.OperationTimeouts, files, workers)
	}
	// A generous wall-clock bound: one idle wave plus drain, never files/workers
	// recovery budgets.
	if budget := 12 * idle; elapsed > budget {
		t.Fatalf("doomed share did not fail fast: %s elapsed, bound %s", elapsed, budget)
	}
	if attempts >= files {
		t.Fatalf("walker kept producing doomed work for an abandoned share: %d/%d attempts", attempts, files)
	}
	// Coverage must be recorded as one representative failure for the whole
	// share, never one entry per doomed object.
	if abandonments != 1 {
		t.Fatalf("expected exactly one abandonment record for the share, got %d", abandonments)
	}
	if perObjectFailures > 4*workers {
		t.Fatalf("doomed objects produced per-object failure records instead of one share record: %d", perObjectFailures)
	}
}

// TestUnhealthyShareDoesNotBlockHealthyShare proves breaker isolation: an
// unhealthy share is abandoned on its own and the healthy share still scans.
func TestUnhealthyShareDoesNotBlockHealthyShare(t *testing.T) {
	srv := newHealthServer()
	srv.addDir("", srv.addFiles("bad", 100)...)
	srv.readStall = true
	client := newHealthClient(t, srv)
	isolateShareBreaker(client)

	badElapsed, _ := drainShare(t, client, "bad", 15)

	// The transport is healthy again for the second share.
	srv.mu.Lock()
	srv.readStall = false
	srv.mu.Unlock()

	healthyElapsed, healthyAttempts := drainShare(t, client, "healthy", 15)
	unhealthyShares, targetUnhealthy, _ := client.healthSnapshot()

	if healthyAttempts == 0 {
		t.Fatal("healthy share was not scanned after the unhealthy share was abandoned")
	}
	if targetUnhealthy {
		t.Fatal("one unhealthy share must not abandon the whole target")
	}
	if unhealthyShares != 1 {
		t.Fatalf("expected exactly one abandoned share, got %d", unhealthyShares)
	}
	if budget := 20 * healthTestIdle(client); badElapsed > budget {
		t.Fatalf("unhealthy share did not fail fast: %s elapsed, bound %s", badElapsed, budget)
	}
	if healthyElapsed > 10*healthTestIdle(client) {
		t.Fatalf("healthy share was delayed by the unhealthy share: %s", healthyElapsed)
	}
}

// TestOrdinaryAccessDeniedNeverAbandonsShare guards the breaker boundary:
// access-denied is an ordinary SMB status, not transport unhealth, so a share
// where every file is denied must still be fully enumerated.
func TestOrdinaryAccessDeniedNeverAbandonsShare(t *testing.T) {
	const files = 60
	srv := newHealthServer()
	names := srv.addFiles("file", files)
	for _, name := range names {
		srv.denied[name] = true
	}
	srv.addDir("", names...)
	client := newHealthClient(t, srv)

	_, attempts := drainShare(t, client, "share", 15)
	unhealthyShares, targetUnhealthy, _ := client.healthSnapshot()

	if unhealthyShares != 0 || targetUnhealthy {
		t.Fatalf("ordinary access denied abandoned health: shares=%d target=%v", unhealthyShares, targetUnhealthy)
	}
	if attempts != files {
		t.Fatalf("access-denied share was not fully enumerated: %d/%d attempts", attempts, files)
	}
}

// TestTransientResetRecoversWithoutAbandoningShare proves an isolated transient
// failure heals instead of condemning a share.
func TestTransientResetRecoversWithoutAbandoningShare(t *testing.T) {
	srv := newFakeServer()
	srv.addFile("share", "A.txt", []byte("alpha"))
	client := NewClient()
	client.dialer = srv
	healthTestTimeouts(client)
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	srv.script(readKey("share", "A.txt"), opScript{err: resetError(), killTrunk: true})
	data, err := client.ReadFile("share", "A.txt")
	if err != nil {
		t.Fatalf("a single transient reset was not recovered: %v", err)
	}
	if string(data) != "alpha" {
		t.Fatalf("recovered read returned %q", data)
	}
	if unhealthyShares, targetUnhealthy, _ := client.healthSnapshot(); unhealthyShares != 0 || targetUnhealthy {
		t.Fatalf("a single transient reset abandoned health: shares=%d target=%v", unhealthyShares, targetUnhealthy)
	}
}

// TestShareRootEnumerationHangIsBounded covers the share-root listing that used
// to run outside every watchdog during share enumeration.
func TestShareRootEnumerationHangIsBounded(t *testing.T) {
	srv := newHealthServer()
	srv.stallDir[""] = true
	client := newHealthClient(t, srv)

	done := make(chan struct{})
	var shares []ShareInfo
	var err error
	go func() {
		defer close(done)
		shares, err = client.ListShares()
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("share enumeration was not bounded: share-root listing wedged outside the watchdog")
	}
	if err == nil {
		t.Fatalf("an unreachable share enumeration must not look successful: shares=%d", len(shares))
	}
}

// TestWalkTreeDisconnectHangIsBounded covers the unbounded tree disconnect at
// the end of a share walk.
func TestWalkTreeDisconnectHangIsBounded(t *testing.T) {
	srv := newHealthServer()
	srv.addDir("", "A.txt")
	srv.addFile("A.txt", []byte("alpha"))
	srv.umountStall = true
	client := newHealthClient(t, srv)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = client.WalkShareWithOptions("share", WalkOptions{}, func(RemoteFile) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("tree disconnect was not bounded: a wedged umount held the target open")
	}
}

// TestReadTotalBudgetBoundsTinyProgress is the tiny-progress infinite-read test:
// a peer that delivers a byte just before each idle deadline must still hit an
// absolute read deadline.
func TestReadTotalBudgetBoundsTinyProgress(t *testing.T) {
	srv := newHealthServer()
	srv.addDir("", "big.txt")
	srv.addFile("big.txt", []byte("seed"))
	srv.tinyProgress = true
	srv.tinyPeriod = 180 * time.Millisecond // < scaled read idle (300ms)
	client := newHealthClient(t, srv)
	isolateShareBreaker(client)
	client.SetMaxReadSize(1 << 20)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := client.ReadFile("share", "big.txt")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a read that never reaches EOF must not be reported as success")
		}
		if max := 60 * time.Second; time.Since(start) > max {
			t.Fatalf("absolute read deadline was not honoured: %s", time.Since(start))
		}
	case <-time.After(60 * time.Second):
		t.Fatal("read stayed alive on tiny periodic progress: no absolute read deadline")
	}
}

// TestUnreachableTargetIsAbandonedPromptly proves a server that cannot be
// reconnected to fails the target once instead of re-dialling per object.
func TestUnreachableTargetIsAbandonedPromptly(t *testing.T) {
	srv := newHealthServer()
	srv.dialErr = resetError()
	client := newHealthClient(t, srv)

	start := time.Now()
	var fast int
	// Each failed reconnect starts a cooldown, so wait one cooldown between
	// attempts exactly as a real scan would.
	deadline := start.Add(20 * time.Second)
	for i := 0; i < 50 && time.Now().Before(deadline); i++ {
		if _, err := client.ReadFile("share", "A.txt"); errors.Is(err, ErrTargetUnhealthy) {
			fast++
			break
		}
		time.Sleep(reconnectCooldown)
	}
	elapsed := time.Since(start)
	if fast == 0 {
		t.Fatal("an unreachable target was never abandoned")
	}
	if !client.targetUnhealthy() {
		t.Fatal("target health was not recorded as unhealthy")
	}
	if elapsed > 20*time.Second {
		t.Fatalf("unreachable target did not fail fast: %s", elapsed)
	}
	if dials := srv.dialCount(); dials > 4 {
		t.Fatalf("unreachable target kept re-dialling: %d dials", dials)
	}
}

// TestManyUnhealthySharesAbandonTarget covers the target-level recovery budget:
// when every share of a target is wedged, each unhealthy share is abandoned but
// the target itself must stop after a bounded amount of continuous transport
// failure instead of paying the per-share cost for every remaining share.
func TestManyUnhealthySharesAbandonTarget(t *testing.T) {
	const shares, filesPerShare, workers = 8, 60, 15
	srv := newHealthServer()
	srv.addDir("", srv.addFiles("file", filesPerShare)...)
	srv.readStall = true
	client := newHealthClient(t, srv)

	var targetAbandonments int64
	client.SetOperationFailureHandler(func(failure OperationFailure) {
		if strings.Contains(strings.ToLower(failure.Operation), "target abandoned") {
			atomic.AddInt64(&targetAbandonments, 1)
		}
	})

	names := make([]string, 0, shares)
	for i := 0; i < shares; i++ {
		names = append(names, fmt.Sprintf("share%02d", i))
	}

	type job struct{ share, path string }
	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				_, _ = client.ReadFile(item.share, item.path)
			}
		}()
	}

	start := time.Now()
	completedShares := 0
	for _, share := range names {
		if err := client.WalkShareWithOptions(share, WalkOptions{}, func(rf RemoteFile) error {
			if rf.IsDir {
				return nil
			}
			jobs <- job{share: rf.Share, path: strings.ReplaceAll(rf.Path, "/", `\`)}
			return nil
		}); err == nil {
			completedShares++
		}
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)

	if !client.targetUnhealthy() {
		t.Fatal("a target where every share is wedged was never abandoned")
	}
	if targetAbandonments != 1 {
		t.Fatalf("expected exactly one target abandonment record, got %d", targetAbandonments)
	}
	if completedShares == shares {
		t.Fatal("target was abandoned only after every share paid its own recovery cost")
	}
	// One abandoned share plus the shared target-recovery window is bounded; it
	// must never be one full recovery budget per share.
	if budget := 30 * healthTestIdle(client); elapsed > budget {
		t.Fatalf("unhealthy target did not fail fast: %s elapsed, bound %s", elapsed, budget)
	}
}

// TestNoGoroutineLeakAfterShareAbandonment proves abandoning a share releases
// every blocked call instead of retaining a goroutine behind the breaker.
func TestNoGoroutineLeakAfterShareAbandonment(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for cycle := 0; cycle < 4; cycle++ {
		srv := newHealthServer()
		srv.addDir("", srv.addFiles("file", 40)...)
		srv.readStall = true
		client := newHealthClient(t, srv)
		isolateShareBreaker(client)
		drainShare(t, client, "share", 15)
		if _, targetUnhealthy, _ := client.healthSnapshot(); targetUnhealthy {
			t.Fatal("a single unhealthy share must not abandon the target")
		}
		_ = client.Close()
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline+8 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines retained after share abandonment: baseline=%d current=%d", baseline, current)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

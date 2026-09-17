package smb

import (
	"context"
	"io"
	"io/fs"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The share-probe protocol trades terminal fail-fast behaviour for bounded
// wait/recovery: queued work for a withheld share waits for one probe instead of
// giving up. That trade is only safe if a granted probe is *always* released.
// These tests pin the invariants of the state machine:
//
//	1. probing=true implies exactly one owner is responsible for resolution
//	2. every grant reaches exactly one terminal transition
//	3. every terminal transition clears probing and wakes every waiter
//	4. no waiter waits longer than the share recovery budget or its own context
//	5. cancellation always beats recovery waiting, and never counts as a verdict
//
// They are deterministic: the only timing dependencies are cooldowns and
// budgets that the test itself sets, and every wait is bounded by a context or a
// share recovery budget.

// probeTestSession is a minimal healthy transport for probe tests. Its tree
// serves whatever content the test puts in the session.
type probeTestSession struct {
	mu      sync.Mutex
	content map[string][]byte
	closed  bool
}

func newProbeTestSession(content map[string][]byte) *probeTestSession {
	if content == nil {
		content = map[string][]byte{}
	}
	return &probeTestSession{content: content}
}

func (s *probeTestSession) Mount(string) (transportTree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fs.ErrClosed
	}
	return &probeTestTree{sess: s}, nil
}

func (s *probeTestSession) ListSharenames() ([]string, error) { return []string{"share-a"}, nil }

func (s *probeTestSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type probeTestTree struct{ sess *probeTestSession }

func (t *probeTestTree) ReadDir(string) ([]fs.FileInfo, error) { return nil, nil }

func (t *probeTestTree) Stat(name string) (fs.FileInfo, error) {
	t.sess.mu.Lock()
	body, ok := t.sess.content[name]
	t.sess.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeFileInfo{name: name, size: int64(len(body))}, nil
}

func (t *probeTestTree) Open(name string) (transportFile, error) {
	t.sess.mu.Lock()
	body, ok := t.sess.content[name]
	t.sess.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &probeTestFile{data: body}, nil
}

func (t *probeTestTree) Umount() error                               { return nil }
func (t *probeTestTree) MkdirAll(string, fs.FileMode) error          { return nil }
func (t *probeTestTree) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (t *probeTestTree) RemoveAll(string) error                      { return nil }

type probeTestFile struct {
	data []byte
	off  int
}

func (f *probeTestFile) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func (f *probeTestFile) Close() error { return nil }

// withheldProbeTestClient returns a client whose share-a is degraded exactly as
// the production containment rule withholds it (three distinct hard-bound
// operations), with the probe cooldown already elapsed.
func withheldProbeTestClient(t *testing.T, cooldown, shareBudget time.Duration) *Client {
	t.Helper()
	c := NewClient()
	c.SetShareProbeCooldown(cooldown)
	c.SetShareRecoveryBudget(shareBudget)
	c.SetTargetRecoveryBudget(time.Hour)
	c.dialAddr = "fileserver.example.test:445"
	c.session = newProbeTestSession(map[string][]byte{"file.txt": []byte("content")})
	withheldBy := 0
	for _, operation := range []string{
		"read a.txt on share-a",
		"read b.txt on share-a",
		"read c.txt on share-a",
	} {
		if c.noteHardTimeout("share-a", operation) {
			withheldBy++
		}
	}
	if withheldBy != 1 {
		t.Fatalf("share was degraded %d times, want exactly one transition", withheldBy)
	}
	c.mu.Lock()
	st := c.health.shares["share-a"]
	if st == nil || st.phase != shareDegraded {
		c.mu.Unlock()
		t.Fatalf("share was not degraded after %d distinct failures", shareFailureStreakLimit)
	}
	st.nextProbeAt = time.Now().Add(-time.Second)
	c.mu.Unlock()
	return c
}

// probeStateOf exposes the explicit containment state in the shape the probe
// tests assert on: degraded is the old "withheld" state.
func probeStateOf(c *Client, share string) (degraded, probing, abandoned bool, nextProbeAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil {
		return false, false, false, time.Time{}
	}
	return st.phase == shareDegraded, st.probing, st.phase == shareAbandoned, st.nextProbeAt
}

// probeChannelState reports whether a probe is still in flight. Every terminal
// transition of the degraded state, including the recovery deadline expiring,
// clears probing and wakes the waiters, so a probe left set is a stranded lease.
func probeChannelState(c *Client, share string) (probing bool, openChannel bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil {
		return false, false
	}
	return st.probing, st.probing
}

// runOperationForTest runs one read-shaped operation on the share and returns
// its result through a channel so the test can bound the wait.
func runOperationForTest(ctx context.Context, c *Client, share, operation string, fn func() error) chan error {
	done := make(chan error, 1)
	go func() {
		done <- c.runOperation(ctx, operation, share, true, func(transportSession, time.Time) error {
			return fn()
		})
	}()
	return done
}

func requireOperationReturns(t *testing.T, done <-chan error, bound time.Duration, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(bound):
		t.Fatalf("%s did not return within %s: the share-probe state machine wedged the caller", what, bound)
		return nil
	}
}

// TestProbeLeaseReleasedWhenOperationBudgetExpires is failure mode A: the
// worker that owns the probe returns through the operation-budget path before
// resolving it. The probe must still be released, and every waiter must learn
// that no probe is in flight any more.
func TestProbeLeaseReleasedWhenOperationBudgetExpires(t *testing.T) {
	const cooldown = 100 * time.Millisecond
	c := withheldProbeTestClient(t, cooldown, 30*time.Second)
	c.SetRecoveryBudget(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Worker 1 owns the probe and blocks inside its operation, so worker 2 must
	// wait for it and can only claim the probe after the cooldown.
	ownerRelease := make(chan struct{})
	owner := runOperationForTest(ctx, c, "share-a", "read owner.txt on share-a", func() error {
		<-ownerRelease
		return deniedError()
	})
	waitForCondition(t, func() bool {
		_, probing, _, _ := probeStateOf(c, "share-a")
		return probing
	}, time.Second, "probe owner never claimed the probe")

	start := time.Now()
	victim := runOperationForTest(ctx, c, "share-a", "read victim.txt on share-a", func() error {
		t.Error("operation budget was exhausted, so the probe must not run")
		return nil
	})
	close(ownerRelease)
	requireOperationReturns(t, owner, 5*time.Second, "probe owner")

	err := requireOperationReturns(t, victim, 5*time.Second, "budget-exhausted probe owner")
	if err == nil {
		t.Fatal("budget-exhausted operation returned success")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("budget-exhausted probe owner took %s to return", time.Since(start))
	}
	if probing, openChannel := probeChannelState(c, "share-a"); probing || openChannel {
		t.Fatalf("probe lease was stranded: probing=%v openProbeChannel=%v after its owner returned", probing, openChannel)
	}
	// A fresh worker must make progress instead of waiting on a probe that can
	// never resolve.
	requireOperationReturns(t, runOperationForTest(ctx, c, "share-a", "read next.txt on share-a", func() error {
		return deniedError()
	}), 5*time.Second, "worker behind a budget-exhausted probe owner")
}

// TestProbeLeaseReleasedWhenSessionUnavailable is failure mode B: the probe
// owner cannot obtain a session (reconnect cooldown / no transport) and returns
// before touching the network. The lease must still be released.
func TestProbeLeaseReleasedWhenSessionUnavailable(t *testing.T) {
	c := withheldProbeTestClient(t, 50*time.Millisecond, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// currentSession fails without any dial attempt: there is no address.
	c.mu.Lock()
	c.session = nil
	c.dialAddr = ""
	c.mu.Unlock()

	done := runOperationForTest(ctx, c, "share-a", "read victim.txt on share-a", func() error {
		t.Error("no session was available, so the probe must not run")
		return nil
	})
	err := requireOperationReturns(t, done, 5*time.Second, "session-unavailable probe owner")
	if err == nil {
		t.Fatal("session-unavailable probe owner returned success")
	}
	if probing, openChannel := probeChannelState(c, "share-a"); probing || openChannel {
		t.Fatalf("probe lease was stranded: probing=%v openProbeChannel=%v after a session failure", probing, openChannel)
	}
}

// TestProbeFailureArmsCooldownAndReleasesWaiters is failure mode C: the probe
// itself fails, so the share stays withheld, the cooldown is re-armed, and the
// waiters are woken to try again.
func TestProbeFailureArmsCooldownAndReleasesWaiters(t *testing.T) {
	const cooldown = 100 * time.Millisecond
	c := withheldProbeTestClient(t, cooldown, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	owner := runOperationForTest(ctx, c, "share-a", "read owner.txt on share-a", func() error {
		return deniedError()
	})
	if err := requireOperationReturns(t, owner, 5*time.Second, "failed probe"); err == nil {
		t.Fatal("failed probe returned success")
	}
	withheld, probing, abandoned, nextProbeAt := probeStateOf(c, "share-a")
	if !withheld || abandoned {
		t.Fatalf("failed probe changed containment: withheld=%v abandoned=%v", withheld, abandoned)
	}
	if probing {
		t.Fatal("failed probe left probing set")
	}
	if !nextProbeAt.After(time.Now()) {
		t.Fatalf("failed probe did not re-arm the cooldown: nextProbeAt=%s", nextProbeAt)
	}
	// The next worker must be able to claim a probe after the cooldown.
	next := runOperationForTest(ctx, c, "share-a", "read next.txt on share-a", func() error {
		return deniedError()
	})
	requireOperationReturns(t, next, 5*time.Second, "worker after a failed probe")
}

// TestProbeSuccessRestoresShareAndReleasesWaiters is failure mode D: a probe
// that succeeds restores the share so the withheld queue resumes.
func TestProbeSuccessRestoresShareAndReleasesWaiters(t *testing.T) {
	c := withheldProbeTestClient(t, 100*time.Millisecond, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := requireOperationReturns(t, runOperationForTest(ctx, c, "share-a", "read owner.txt on share-a", func() error {
		return nil
	}), 5*time.Second, "successful probe"); err != nil {
		t.Fatalf("successful probe failed: %v", err)
	}
	withheld, probing, abandoned, nextProbeAt := probeStateOf(c, "share-a")
	if withheld || probing || abandoned {
		t.Fatalf("successful probe did not restore the share: withheld=%v probing=%v abandoned=%v", withheld, probing, abandoned)
	}
	if !nextProbeAt.IsZero() {
		t.Fatalf("successful probe left a pending cooldown: nextProbeAt=%s", nextProbeAt)
	}
	requireOperationReturns(t, runOperationForTest(ctx, c, "share-a", "read next.txt on share-a", func() error {
		return nil
	}), 5*time.Second, "worker after a successful probe")
}

// countingContext counts how often the wait loop observes the context, which is
// exactly the tight-loop signature of a zero-duration timer.
type countingContext struct {
	context.Context
	doneCalls atomic.Int64
}

func (c *countingContext) Done() <-chan struct{} {
	c.doneCalls.Add(1)
	return c.Context.Done()
}

// TestNoBusySpinWhileProbeIsInFlight is failure mode H: with a probe in flight
// and an already-expired nextProbeAt, waiters must block on the probe, the
// withheld deadline or cancellation instead of spinning on a zero timer.
func TestNoBusySpinWhileProbeIsInFlight(t *testing.T) {
	c := withheldProbeTestClient(t, 100*time.Millisecond, 30*time.Second)
	c.mu.Lock()
	st := c.health.shares["share-a"]
	st.nextProbeAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	base, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	counting := &countingContext{Context: base}
	ctx := context.Context(counting)

	ownerRelease := make(chan struct{})
	owner := runOperationForTest(ctx, c, "share-a", "read owner.txt on share-a", func() error {
		<-ownerRelease
		return deniedError()
	})
	waitForCondition(t, func() bool {
		_, probing, _, _ := probeStateOf(c, "share-a")
		return probing
	}, time.Second, "probe owner never claimed the probe")

	waiter := runOperationForTest(ctx, c, "share-a", "read waiter.txt on share-a", func() error {
		return deniedError()
	})
	time.Sleep(150 * time.Millisecond)
	if calls := counting.doneCalls.Load(); calls > 5000 {
		t.Fatalf("waiters spun on an expired probe timer: %d context observations while one probe was in flight", calls)
	}
	select {
	case <-waiter:
		t.Fatal("waiter returned while another worker still owned the probe")
	default:
	}
	close(ownerRelease)
	requireOperationReturns(t, owner, 5*time.Second, "probe owner")
	requireOperationReturns(t, waiter, 5*time.Second, "waiter behind an in-flight probe")
}

// TestWithheldWatchdogReleasesWaiters is the secondary safety net: if the probe
// owner never resolves for any reason, the degraded state itself must expire and
// release every waiter instead of holding them forever.
func TestWithheldWatchdogReleasesWaiters(t *testing.T) {
	const (
		cooldown    = 20 * time.Millisecond
		shareBudget = 300 * time.Millisecond
	)
	c := withheldProbeTestClient(t, cooldown, shareBudget)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A probe owner that never resolves: the lease is held, and the state
	// machine itself must still expire the degraded state.
	c.mu.Lock()
	st := c.health.shares["share-a"]
	st.probing = true
	c.mu.Unlock()

	waiters := make([]chan error, 15)
	for i := range waiters {
		waiters[i] = runOperationForTest(ctx, c, "share-a", "read waiter.txt on share-a", func() error {
			return deniedError()
		})
	}
	start := time.Now()
	for i, waiter := range waiters {
		if err := requireOperationReturns(t, waiter, 5*time.Second, "waiter behind a never-resolving probe"); err == nil {
			t.Fatalf("waiter %d returned success while the share was withheld", i)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 4*time.Second {
		t.Fatalf("withheld watchdog did not bound the wait: %s", elapsed)
	}
	withheld, _, abandoned, _ := probeStateOf(c, "share-a")
	if probing, openChannel := probeChannelState(c, "share-a"); probing || openChannel {
		t.Fatalf("watchdog left the probe in flight: probing=%v openProbeChannel=%v", probing, openChannel)
	}
	if withheld && !abandoned {
		t.Fatal("watchdog neither restored nor abandoned the share")
	}
}

// TestFifteenWorkersReleasedForEveryProbeOutcome is the concurrency acceptance
// test: whatever happens to the granted probe, all workers waiting behind it
// must be released and probing must end up false.
func TestFifteenWorkersReleasedForEveryProbeOutcome(t *testing.T) {
	const workers = 15
	cases := []struct {
		name string
		run  func(t *testing.T, c *Client, ctx context.Context) []chan error
	}{
		{
			name: "probe succeeds",
			run: func(t *testing.T, c *Client, ctx context.Context) []chan error {
				out := make([]chan error, workers)
				for i := range out {
					out[i] = runOperationForTest(ctx, c, "share-a", "read file.txt on share-a", func() error { return nil })
				}
				return out
			},
		},
		{
			name: "probe fails",
			run: func(t *testing.T, c *Client, ctx context.Context) []chan error {
				out := make([]chan error, workers)
				for i := range out {
					out[i] = runOperationForTest(ctx, c, "share-a", "read file.txt on share-a", func() error { return deniedError() })
				}
				return out
			},
		},
		{
			name: "probe budget exhausted",
			run: func(t *testing.T, c *Client, ctx context.Context) []chan error {
				c.SetRecoveryBudget(10 * time.Millisecond)
				out := make([]chan error, workers)
				for i := range out {
					out[i] = runOperationForTest(ctx, c, "share-a", "read file.txt on share-a", func() error { return deniedError() })
				}
				return out
			},
		},
		{
			name: "probe session unavailable",
			run: func(t *testing.T, c *Client, ctx context.Context) []chan error {
				c.mu.Lock()
				c.session = nil
				c.dialAddr = ""
				c.mu.Unlock()
				out := make([]chan error, workers)
				for i := range out {
					out[i] = runOperationForTest(ctx, c, "share-a", "read file.txt on share-a", func() error { return nil })
				}
				return out
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := withheldProbeTestClient(t, 20*time.Millisecond, 30*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			results := tc.run(t, c, ctx)
			for i, result := range results {
				requireOperationReturns(t, result, 10*time.Second, "worker "+strconv.Itoa(i))
			}
			if probing, openChannel := probeChannelState(c, "share-a"); probing || openChannel {
				t.Fatalf("probe was left in flight after every worker was released: probing=%v openProbeChannel=%v", probing, openChannel)
			}
		})
	}

	t.Run("probe cancelled", func(t *testing.T) {
		c := withheldProbeTestClient(t, 20*time.Millisecond, 30*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		results := make([]chan error, workers)
		for i := range results {
			results[i] = runOperationForTest(ctx, c, "share-a", "read file.txt on share-a", func() error {
				return deniedError()
			})
		}
		time.Sleep(20 * time.Millisecond)
		cancel()
		for i, result := range results {
			requireOperationReturns(t, result, 5*time.Second, "cancelled worker "+strconv.Itoa(i))
		}
		waitForCondition(t, func() bool {
			_, probing, _, _ := probeStateOf(c, "share-a")
			return !probing
		}, 5*time.Second, "probing was left set after cancellation")
	})
}

// TestWaitShareReadyHonoursContextCancellation is failure mode E: cancellation
// must interrupt a containment wait promptly instead of leaving the walker
// blocked for the whole recovery budget.
func TestWaitShareReadyHonoursContextCancellation(t *testing.T) {
	c := withheldProbeTestClient(t, time.Hour, 30*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.waitShareReady(ctx, "share-a") }()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled containment wait returned success")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("cancellation took %s to release the containment wait", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled containment wait did not return")
	}
}

func waitForCondition(t *testing.T, condition func() bool, bound time.Duration, message string) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}

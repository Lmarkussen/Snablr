package smb

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// freezeHarnessGrace is the CI-safe allowance added to the configured share
// recovery budget when a test asserts that a share reached its terminal state.
// It covers one detection window, the bounded cleanup of in-flight phases and
// scheduler jitter. The production requirement is unchanged: a single share may
// only hold target progress for its recovery budget plus a small cleanup grace,
// and never for the tens of minutes the live scanner spent on one share.
const freezeHarnessGrace = 8 * time.Second

// freezeCountingContext counts how often the wait loop observes the context,
// which is the tight-loop signature of a zero-duration timer.
type freezeCountingContext struct {
	context.Context
	doneCalls atomic.Int64
}

func (c *freezeCountingContext) Done() <-chan struct{} {
	c.doneCalls.Add(1)
	return c.Context.Done()
}

// TestFreezeHarnessLaterShareStartsAfterWedgedShare is the live failure
// reproduction: one target, a healthy share, a share whose transport calls
// wedge in a way session invalidation cannot release, and a later healthy
// share. Thousands of files are queued for the wedged share so the walker
// blocks on queue backpressure mid-walk, exactly as the live scanner did.
//
// The target must still reach the later healthy share inside the configured
// share recovery policy, and the later share's content controls must be found.
func TestFreezeHarnessLaterShareStartsAfterWedgedShare(t *testing.T) {
	for _, fileCount := range []int{1200, 2600} {
		fileCount := fileCount
		t.Run(fmt.Sprintf("files-%d", fileCount), func(t *testing.T) {
			srv := newFreezeServer()
			srv.addShare("share-a")
			healthyPadding(srv, "share-a", 40)
			seedControlFiles(srv, "share-a")
			srv.addShare("share-b")
			healthyPadding(srv, "share-b", fileCount)
			srv.addShare("share-c")
			healthyPadding(srv, "share-c", 40)
			seedControlFiles(srv, "share-c")

			client, failures := newFreezeClient(t, srv)
			shareBudget := client.shareRecoveryLimitLocked()
			client.SetShareProbeCooldown(100 * time.Millisecond)
			client.SetShareRecoveryBudget(shareBudget)
			client.SetTargetRecoveryBudget(time.Hour)

			srv.wedgeShareName("share-b")
			sink := newFreezeSink()
			engine := newFreezeEngine(t, sink)

			bound := shareBudget + freezeHarnessGrace
			start := time.Now()
			_ = runFreezeTargetBounded(t, context.Background(), client, engine, sink, []string{"share-a", "share-b", "share-c"}, 15, bound)
			elapsed := time.Since(start)

			started, ok := sink.shareStarted("share-c")
			if !ok {
				t.Fatalf("the later healthy share never started; shares tried: %v", sink.sharesStarted())
			}
			if since := started.Sub(start); since > bound {
				t.Fatalf("later healthy share started %s after the target began, beyond the share recovery bound %s", since, bound)
			}
			if elapsed > bound {
				t.Fatalf("target took %s to complete, beyond the share recovery bound %s", elapsed, bound)
			}
			if got := failures.abandonmentFor("share-b"); got != 1 {
				t.Fatalf("wedged share produced %d abandonment records, want exactly 1", got)
			}
			if abandoned, _, _ := client.healthSnapshot(); abandoned == 0 {
				t.Fatal("wedged share was not recorded as terminal containment")
			}
			if wedged := srv.wedgedOps.Load(); wedged > int64(4*shareFailureStreakLimit*15) {
				t.Fatalf("%d file operations were left to pay the phase bound on a dead share", wedged)
			}
			if srv.fileCount("share-b") < 1000 {
				t.Fatalf("harness did not queue 1000+ files for the wedged share: %d", srv.fileCount("share-b"))
			}
			requireControlFindings(t, sink)
			requireControlReads(t, sink, "share-c")
			requireControlReads(t, sink, "share-a")
			if len(sink.sharesStarted()) == 0 {
				t.Fatal("no share was walked")
			}
		})
	}
}

// TestFreezeHarnessCancellationWhileWorkersWedgedAndQueueFull is the
// cancellation acceptance test for the live shape: every worker is inside a
// wedged call and the walker is blocked on a full queue. Cancellation must
// release all of it in seconds, never by waiting out the recovery budget.
func TestFreezeHarnessCancellationWhileWorkersWedgedAndQueueFull(t *testing.T) {
	srv := newFreezeServer()
	srv.addShare("share-a")
	healthyPadding(srv, "share-a", 20)
	srv.addShare("share-b")
	healthyPadding(srv, "share-b", 2600)

	client, _ := newFreezeClient(t, srv)
	client.SetShareRecoveryBudget(30 * time.Second)
	srv.wedgeShareName("share-b")

	sink := newFreezeSink()
	engine := newFreezeEngine(t, sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runFreezeTarget(ctx, client, engine, sink, []string{"share-a", "share-b"}, 15)
	}()

	// Wait until the wedged share is being walked and its calls are wedged.
	deadline := time.Now().Add(10 * time.Second)
	for srv.wedgedOps.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("harness never wedged a share operation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("cancelled target took %s to exit", elapsed)
		}
		if err == nil {
			t.Fatal("cancelled target reported success")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("cancelled target did not exit: workers or the walker were wedged past cancellation")
	}
}

// TestFreezeHarnessTransientWedgeKeepsControlRecall proves the opposite
// property: a share that is briefly unwell must be recovered, not abandoned,
// and the content controls that follow the fault must still be found.
func TestFreezeHarnessTransientWedgeKeepsControlRecall(t *testing.T) {
	srv := newFreezeServer()
	srv.addShare("share-a")
	healthyPadding(srv, "share-a", 60)
	seedControlFiles(srv, "share-a")

	client, failures := newFreezeClient(t, srv)
	client.SetShareProbeCooldown(100 * time.Millisecond)
	client.SetShareRecoveryBudget(2 * time.Second)
	client.SetTargetRecoveryBudget(time.Hour)

	srv.wedgeShareName("share-a")
	go func() {
		time.Sleep(400 * time.Millisecond)
		srv.healShare("share-a")
	}()

	sink := newFreezeSink()
	engine := newFreezeEngine(t, sink)
	if err := runFreezeTargetBounded(t, context.Background(), client, engine, sink, []string{"share-a"}, 15, 2*time.Second+freezeHarnessGrace); err != nil {
		t.Fatalf("a recoverable transport window failed the share: %v", err)
	}
	if failures.abandonmentFor("share-a") != 0 {
		t.Fatalf("a recoverable transport window abandoned the share: %v", failures.snapshot())
	}
	stats := client.TransportStats()
	if stats.SharesWithheld == 0 {
		t.Fatal("the transport window did not degrade the share")
	}
	if stats.SharesAbandoned != 0 {
		t.Fatalf("recoverable containment abandoned the share: %#v", stats)
	}
	requireControlFindings(t, sink)
	requireControlReads(t, sink, "share-a")
}

// TestFreezeHarnessUmountStallDoesNotBlockTarget covers cleanup: every scan
// phase completing and the tree disconnect wedging must not hold the target.
func TestFreezeHarnessUmountStallDoesNotBlockTarget(t *testing.T) {
	srv := newFreezeServer()
	srv.addShare("share-a")
	healthyPadding(srv, "share-a", 30)
	seedControlFiles(srv, "share-a")

	client, _ := newFreezeClient(t, srv)
	srv.stallFirstUmount(harnessWedgeTTL)

	sink := newFreezeSink()
	engine := newFreezeEngine(t, sink)
	if err := runFreezeTargetBounded(t, context.Background(), client, engine, sink, []string{"share-a"}, 15, freezeHarnessGrace); err != nil {
		t.Fatalf("healthy share failed while a tree disconnect stalled: %v", err)
	}
	if srv.umounts.Load() == 0 {
		t.Fatal("harness never stalled a tree disconnect")
	}
	requireControlFindings(t, sink)
	requireControlReads(t, sink, "share-a")
}

// TestFreezeHarnessLogoffStallDoesNotBlockTarget covers target completion: a
// logoff that never answers must not hold the scan.
func TestFreezeHarnessLogoffStallDoesNotBlockTarget(t *testing.T) {
	srv := newFreezeServer()
	srv.addShare("share-a")
	healthyPadding(srv, "share-a", 20)
	seedControlFiles(srv, "share-a")

	client, _ := newFreezeClient(t, srv)
	srv.stallLogoff(harnessWedgeTTL)

	sink := newFreezeSink()
	engine := newFreezeEngine(t, sink)
	if err := runFreezeTargetBounded(t, context.Background(), client, engine, sink, []string{"share-a"}, 15, freezeHarnessGrace); err != nil {
		t.Fatalf("healthy share failed while a logoff stalled: %v", err)
	}
	requireControlFindings(t, sink)
	requireControlReads(t, sink, "share-a")

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("client close reported an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client close waited for a logoff the peer never answered")
	}
	settle := time.Now().Add(2 * time.Second)
	for srv.closes.Load() == 0 && time.Now().Before(settle) {
		time.Sleep(10 * time.Millisecond)
	}
	srv.releaseAll()
}

// TestFreezeHarnessContainmentWaitersParkNotSpin proves waiters park on the
// state-change channel and the absolute recovery deadline instead of spinning.
// A probe owner that hangs while holding the lease is the trigger: when it
// finally resolves, every waiter is woken at once and must re-park for the
// remaining recovery window rather than loop on a zero-duration timer.
func TestFreezeHarnessContainmentWaitersParkNotSpin(t *testing.T) {
	srv := newFreezeServer()
	srv.addShare("share-a")
	seedControlFiles(srv, "share-a")
	srv.addFile("share-a", "waiter.txt", "Password=Synthetic-Waiter-123!")

	client, _ := newFreezeClient(t, srv)
	client.SetShareProbeCooldown(time.Nanosecond)
	client.SetShareRecoveryBudget(3 * time.Second)
	client.SetTargetRecoveryBudget(time.Hour)

	// Three distinct hard-bound operations degrade the share through the normal
	// production rule.
	for i := 0; i < shareFailureStreakLimit; i++ {
		client.noteHardTimeout("share-a", fmt.Sprintf("read stall%02d.txt on share-a", i))
	}

	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	counting := &freezeCountingContext{Context: base}
	ctx := context.Context(counting)

	// A probe owner claims the lease and hangs inside its operation. It resolves
	// later, which wakes every waiter parked behind the probe.
	ownerRelease := make(chan struct{})
	owner := drainOperationWith(ctx, client, "owner.txt", func() error {
		<-ownerRelease
		return fmt.Errorf("synthetic probe failure")
	})
	waitForCondition(t, func() bool {
		_, probing, _, _ := probeStateOf(client, "share-a")
		return probing
	}, 2*time.Second, "probe owner never claimed the lease")

	waiters := make([]chan error, 15)
	for i := range waiters {
		path := fmt.Sprintf("waiter%02d.txt", i)
		waiters[i] = drainOperation(ctx, client, path)
	}
	// Wake every waiter well past half of the recovery budget. The pre-fix
	// waiter loop recomputed a withheld deadline that had already drifted into
	// the past; a long cooldown also keeps any waiter from claiming a probe of
	// its own here, so every wake-up must be a real park.
	time.Sleep(2200 * time.Millisecond)
	client.SetShareProbeCooldown(time.Hour)
	close(ownerRelease)
	time.Sleep(600 * time.Millisecond)
	if calls := counting.doneCalls.Load(); calls > 5000 {
		t.Fatalf("containment waiters spun on a zero-duration timer: %d context observations", calls)
	}
	requireOperationReturns(t, owner, 5*time.Second, "failed probe owner")
	for i, waiter := range waiters {
		select {
		case err := <-waiter:
			if err == nil {
				t.Fatalf("waiter %d returned success while the share was degraded", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d was not released by the share recovery deadline", i)
		}
	}
	if _, _, abandoned, _ := probeStateOf(client, "share-a"); !abandoned {
		t.Fatal("share was not abandoned when the recovery deadline elapsed")
	}
	// The containment loop re-examined the share once per waiter per state
	// change. A spinning waiter would have re-examined it on every loop.
	if iterations := client.containmentWaitIterations("share-a"); iterations > 200 {
		t.Fatalf("containment waiters re-examined the share %d times", iterations)
	}
}

// TestFreezeHarnessNoGoroutineLeak proves the abandoned transport calls are
// released instead of accumulating, once the harness lets them finish.
func TestFreezeHarnessNoGoroutineLeak(t *testing.T) {
	baseline := runtime.NumGoroutine()

	srv := newFreezeServer()
	srv.addShare("share-a")
	healthyPadding(srv, "share-a", 20)
	srv.addShare("share-b")
	healthyPadding(srv, "share-b", 1200)

	client, _ := newFreezeClient(t, srv)
	client.SetShareProbeCooldown(50 * time.Millisecond)
	client.SetShareRecoveryBudget(600 * time.Millisecond)
	client.SetTargetRecoveryBudget(time.Hour)
	srv.wedgeShareName("share-b")

	sink := newFreezeSink()
	engine := newFreezeEngine(t, sink)
	_ = runFreezeTargetBounded(t, context.Background(), client, engine, sink, []string{"share-a", "share-b"}, 15, 600*time.Millisecond+freezeHarnessGrace)

	srv.releaseAll()
	_ = client.Close()
	requireGoroutinesSettle(t, baseline, 5*time.Second)
}

func drainOperation(ctx context.Context, client *Client, path string) chan error {
	return drainOperationWith(ctx, client, path, func() error { return nil })
}

func drainOperationWith(ctx context.Context, client *Client, path string, fn func() error) chan error {
	done := make(chan error, 1)
	go func() {
		done <- client.runOperation(ctx, "read "+path+" on share-a", "share-a", true, func(transportSession, time.Time) error {
			return fn()
		})
	}()
	return done
}

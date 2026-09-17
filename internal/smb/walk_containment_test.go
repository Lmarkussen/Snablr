package smb

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// These tests pin the walker side of the share-probe state machine: caller
// cancellation must always beat a containment wait, and a share that is
// withheld (transiently or permanently) must never stop a later share of the
// same target from being enumerated and read.

// TestWalkerExitsOnContextCancellation proves that a walk parked on a withheld
// share honours the caller's context end to end: the mount wait is a
// containment wait, so Ctrl-C and --max-scan-time must release it.
func TestWalkerExitsOnContextCancellation(t *testing.T) {
	c := withheldProbeTestClient(t, time.Hour, 30*time.Minute)
	// Keep the probe cooldown in the future so the walk parks in the
	// containment wait instead of claiming the probe immediately.
	c.mu.Lock()
	c.health.shares["share-a"].nextProbeAt = time.Now().Add(time.Hour)
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.WalkShareWithOptionsContext(ctx, "share-a", WalkOptions{}, func(RemoteFile) error { return nil })
	}()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled walk reported success")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("cancellation took %s to release a walk parked on a withheld share", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("walk stayed parked on a withheld share after cancellation")
	}
}

// TestProbeLeaseReleasedWhenOwnerPanics is failure mode G: a probe owner that
// panics must still release its lease, because the release is deferred rather
// than written into each return path.
func TestProbeLeaseReleasedWhenOwnerPanics(t *testing.T) {
	c := withheldProbeTestClient(t, 50*time.Millisecond, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	panicResult := make(chan any, 1)
	go func() {
		defer func() { panicResult <- recover() }()
		_ = c.runOperation(ctx, "read owner.txt on share-a", "share-a", true, func(transportSession, time.Time) error {
			panic("synthetic probe panic")
		})
	}()
	select {
	case recovered := <-panicResult:
		if recovered == nil {
			t.Fatal("probe operation did not panic, so the test proved nothing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("panicking probe owner did not unwind")
	}
	if _, probing, _, _ := probeStateOf(c, "share-a"); probing {
		t.Fatal("panicking probe owner stranded its lease")
	}
}

// TestLaterShareScansAfterTransientContainment is the target-level recall
// regression: share-a is briefly unwell and recovers, and share-b must still be
// enumerated and read afterwards.
func TestLaterShareScansAfterTransientContainment(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 1; i <= 120; i++ {
		srv.add(fmt.Sprintf("file%03d.txt", i), "nothing interesting here")
	}
	srv.add("settings.ini", "AdminPassword=Synthetic-Admin-123!")
	srv.add("OperationsGuide.docx", "Passordet er; Synthetic-Docx-123!")
	srv.add("notes.txt", "Password=Synthetic-Txt-123!")
	srv.degradeAfterOK = 40
	srv.degradeFor = 600 * time.Millisecond

	client := recallTestClient(t, srv)
	readA, failedA, _, walkErrA := scanShareMirroringApp(t, client, "share-a", 15)
	if walkErrA != nil {
		t.Fatalf("share-a walk failed after a recoverable transport window: %v", walkErrA)
	}
	for _, control := range []string{"settings.ini", "OperationsGuide.docx", "notes.txt"} {
		requireRead(t, readA, failedA, control)
	}

	// The transport is healthy again before the later share is walked.
	srv.mu.Lock()
	srv.degradeFor = 0
	srv.degradeAt = time.Time{}
	srv.mu.Unlock()

	readB, failedB, enumeratedB, walkErrB := scanShareMirroringApp(t, client, "share-b", 15)
	if walkErrB != nil {
		t.Fatalf("later healthy share failed after share-a containment: %v", walkErrB)
	}
	if len(enumeratedB) == 0 {
		t.Fatal("later healthy share was never enumerated")
	}
	for _, control := range []string{"settings.ini", "OperationsGuide.docx", "notes.txt"} {
		requireRead(t, readB, failedB, control)
	}
}

// TestLaterShareScansAfterPermanentShareAbandonment is the permanent-failure
// bound: a share that never recovers is abandoned within its recovery budget,
// and the target still progresses to the next share.
func TestLaterShareScansAfterPermanentShareAbandonment(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 1; i <= 400; i++ {
		srv.add(fmt.Sprintf("file%03d.txt", i), "nothing interesting here")
	}
	srv.add("settings.ini", "AdminPassword=Synthetic-Admin-123!")
	srv.add("OperationsGuide.docx", "Passordet er; Synthetic-Docx-123!")
	srv.add("notes.txt", "Password=Synthetic-Txt-123!")
	srv.degradeAfterOK = 1
	srv.degradeFor = time.Hour

	client := recallTestClient(t, srv)
	client.SetShareProbeCooldown(50 * time.Millisecond)
	client.SetShareRecoveryBudget(600 * time.Millisecond)

	start := time.Now()
	_, _, _, walkErrA := scanShareMirroringApp(t, client, "share-a", 15)
	if walkErrA == nil {
		t.Fatal("a permanently dead share should be abandoned")
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("permanently dead share was not abandoned within its bound: %s", elapsed)
	}
	if _, probing, abandoned, _ := probeStateOf(client, "share-a"); probing || !abandoned {
		t.Fatalf("abandoned share state is inconsistent: probing=%v abandoned=%v", probing, abandoned)
	}

	srv.mu.Lock()
	srv.degradeFor = 0
	srv.degradeAt = time.Time{}
	srv.mu.Unlock()

	readB, failedB, enumeratedB, walkErrB := scanShareMirroringApp(t, client, "share-b", 15)
	if walkErrB != nil {
		t.Fatalf("later healthy share failed after share-a abandonment: %v", walkErrB)
	}
	if len(enumeratedB) == 0 {
		t.Fatal("later healthy share was never enumerated")
	}
	for _, control := range []string{"settings.ini", "OperationsGuide.docx", "notes.txt"} {
		requireRead(t, readB, failedB, control)
	}
}

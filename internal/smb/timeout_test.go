package smb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func TestIdleWatchdogCancelsOnlyWithoutProgress(t *testing.T) {
	w := newIdleWatchdog(context.Background(), 80*time.Millisecond)
	defer w.stop()
	for i := 0; i < 5; i++ {
		time.Sleep(40 * time.Millisecond)
		if w.ctx.Err() != nil {
			t.Fatal("watchdog fired although progress was reported")
		}
		w.touch()
	}
	select {
	case <-w.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchdog did not fire after the idle timeout")
	}
}

func TestIdleWatchdogFollowsParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	w := newIdleWatchdog(parent, time.Hour)
	defer w.stop()
	cancel()
	select {
	case <-w.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("watchdog ignored scan cancellation")
	}
}

func contextError() error {
	return &os.PathError{Op: "read", Path: "file", Err: &smb2.ContextError{Err: context.Canceled}}
}

func TestObserveClassifiesTimeoutsAndMarksHostUnresponsive(t *testing.T) {
	client := NewClient()
	client.SetOperationContext(context.Background(), 2*time.Second)

	if err := client.observe(contextError()); !errors.Is(err, ErrOperationTimeout) || errors.Is(err, ErrHostUnresponsive) {
		t.Fatalf("first timeout misclassified: %v", err)
	}
	// Any answer from the server resets the count.
	if err := client.observe(&os.PathError{Op: "open", Path: "x", Err: os.ErrPermission}); errors.Is(err, ErrOperationTimeout) {
		t.Fatalf("server answer classified as timeout: %v", err)
	}
	for i := 0; i < unresponsiveAfterTimeouts-1; i++ {
		if err := client.observe(contextError()); errors.Is(err, ErrHostUnresponsive) {
			t.Fatalf("host marked unresponsive after %d consecutive timeouts", i+1)
		}
	}
	err := client.observe(contextError())
	if !errors.Is(err, ErrHostUnresponsive) || !errors.Is(err, ErrOperationTimeout) {
		t.Fatalf("host not marked unresponsive after %d consecutive timeouts: %v", unresponsiveAfterTimeouts, err)
	}
	if _, err := client.operationWatchdog(); !errors.Is(err, ErrHostUnresponsive) {
		t.Fatalf("operations on an unresponsive host did not fail fast: %v", err)
	}
}

func TestObserveReportsScanCancellationAsInterruption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := NewClient()
	client.SetOperationContext(ctx, time.Minute)
	cancel()
	err := client.observe(contextError())
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrOperationTimeout) {
		t.Fatalf("scan cancellation misclassified: %v", err)
	}
	if _, err := client.operationWatchdog(); !errors.Is(err, context.Canceled) {
		t.Fatalf("new operations after cancellation did not stop: %v", err)
	}
	if client.unresponsive {
		t.Fatal("scan cancellation must not mark the host unresponsive")
	}
}

type stallingReader struct {
	data []byte
	sent bool
}

func (r *stallingReader) Read(b []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(b, r.data), nil
	}
	return 0, &os.PathError{Op: "read", Path: "file", Err: &smb2.ContextError{Err: context.Canceled}}
}

// A read that stalls after delivering some data must fail; treating it as
// end-of-file would inspect a silently truncated file and mark it complete.
func TestReadFileContentDoesNotTreatTimeoutAsEndOfFile(t *testing.T) {
	data, err := readFileContent(&stallingReader{data: []byte("partial content")}, 0)
	if err == nil {
		t.Fatalf("timed-out read returned %q as complete content", data)
	}
	// A plain status after data is still treated as end-of-stream.
	data, err = readFileContent(io.MultiReader(bytes.NewReader([]byte("whole file")), trailerStatusReader{}), 0)
	if err != nil || string(data) != "whole file" {
		t.Fatalf("trailing status after data was not kept as end-of-stream: %q %v", data, err)
	}
}

type trailerStatusReader struct{}

func (trailerStatusReader) Read([]byte) (int, error) {
	return 0, errors.New("STATUS_END_OF_FILE style trailer")
}

// Once the host is marked unresponsive, operations still waiting on it end at
// once instead of each waiting out its own timeout. A new connection starts
// with a fresh signal.
func TestUnresponsiveHostEndsOperationsInFlight(t *testing.T) {
	client := NewClient()
	client.SetOperationContext(context.Background(), time.Minute)
	inFlight, err := client.operationWatchdog()
	if err != nil {
		t.Fatal(err)
	}
	defer inFlight.stop()

	for i := 0; i < unresponsiveAfterTimeouts; i++ {
		_ = client.observe(contextError())
	}
	select {
	case <-inFlight.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("operation in flight kept waiting after the host was marked unresponsive")
	}
	if err := client.observe(contextError()); !errors.Is(err, ErrHostUnresponsive) {
		t.Fatalf("ended operation not reported as unresponsive host: %v", err)
	}

	client.mu.Lock()
	client.unresponsive, client.consecutiveTimeouts = false, 0
	client.resetHostDownLocked()
	client.mu.Unlock()
	fresh, err := client.operationWatchdog()
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.stop()
	if fresh.ctx.Err() != nil {
		t.Fatal("operation on a new connection started cancelled")
	}
}

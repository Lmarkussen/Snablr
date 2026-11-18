package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hirochachacha/go-smb2"
)

const (
	// DefaultOperationTimeout bounds a single SMB operation, and is the idle
	// limit for reads and directory listings: they fail only when no data has
	// arrived for this long, so slow but progressing transfers continue.
	DefaultOperationTimeout = 60 * time.Second

	// unresponsiveAfterTimeouts is the number of consecutive timed-out
	// operations after which a host is treated as unresponsive.
	unresponsiveAfterTimeouts = 3

	// cleanupTimeout bounds best-effort cleanup (close, unmount, logoff), which
	// is attempted even after the scan was cancelled. A responsive server
	// answers in milliseconds; an unresponsive one must not delay shutdown.
	cleanupTimeout = 2 * time.Second
)

var (
	// ErrOperationTimeout reports an SMB operation that made no progress
	// within the operation timeout.
	ErrOperationTimeout = errors.New("SMB operation timed out")

	// ErrHostUnresponsive reports that the host stopped answering SMB
	// requests; later operations on the client fail immediately.
	ErrHostUnresponsive = errors.New("SMB host stopped responding")
)

// idleWatchdog is a context that is cancelled when touch has not been called
// for timeout. Operations stay on the caller's goroutine; the watchdog only
// cancels their context, which go-smb2 honours for every request it waits on.
type idleWatchdog struct {
	ctx     context.Context
	cancel  context.CancelFunc
	timer   *time.Timer
	timeout time.Duration
}

func newIdleWatchdog(parent context.Context, timeout time.Duration) *idleWatchdog {
	ctx, cancel := context.WithCancel(parent)
	w := &idleWatchdog{ctx: ctx, cancel: cancel, timeout: timeout}
	if timeout > 0 {
		w.timer = time.AfterFunc(timeout, cancel)
	}
	return w
}

// touch records progress and restarts the idle period.
func (w *idleWatchdog) touch() {
	if w.timer != nil && w.ctx.Err() == nil {
		w.timer.Reset(w.timeout)
	}
}

func (w *idleWatchdog) stop() {
	if w.timer != nil {
		w.timer.Stop()
	}
	w.cancel()
}

// progressReader restarts the watchdog whenever data arrives.
type progressReader struct {
	r io.Reader
	w *idleWatchdog
}

func (p progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.w.touch()
	}
	return n, err
}

// SetOperationContext sets the context that cancels in-flight SMB operations
// (scan interruption or deadline) and the per-operation timeout. A timeout of
// zero keeps the default.
func (c *Client) SetOperationContext(ctx context.Context, timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	c.baseCtx = ctx
	if timeout > 0 {
		c.opTimeout = timeout
	}
}

func (c *Client) operationSettings() (context.Context, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx := c.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx, c.opTimeout
}

// operationWatchdog starts an idle watchdog for one SMB operation, or fails
// immediately when the host is already known to be unresponsive or the scan
// was cancelled.
func (c *Client) operationWatchdog() (*idleWatchdog, error) {
	c.mu.Lock()
	unresponsive := c.unresponsive
	c.mu.Unlock()
	if unresponsive {
		return nil, ErrHostUnresponsive
	}
	base, timeout := c.operationSettings()
	if err := base.Err(); err != nil {
		return nil, err
	}
	return newIdleWatchdog(base, timeout), nil
}

// observe classifies the result of an SMB operation. A request cancelled by
// the scan context is returned wrapped with that context's error so callers
// recognise interruption; a request cancelled by the watchdog is a timeout.
// Consecutive timeouts mark the host unresponsive; any answer from the server
// resets the count.
func (c *Client) observe(err error) error {
	var contextErr *smb2.ContextError
	if err == nil || !errors.As(err, &contextErr) {
		c.mu.Lock()
		c.consecutiveTimeouts = 0
		c.mu.Unlock()
		return err
	}
	base, timeout := c.operationSettings()
	if baseErr := base.Err(); baseErr != nil {
		return fmt.Errorf("%w (%v)", baseErr, err)
	}
	c.mu.Lock()
	c.consecutiveTimeouts++
	if c.consecutiveTimeouts >= unresponsiveAfterTimeouts {
		c.unresponsive = true
	}
	unresponsive := c.unresponsive
	c.mu.Unlock()
	if unresponsive {
		return fmt.Errorf("%w: %w after %s without progress (%v)", ErrHostUnresponsive, ErrOperationTimeout, timeout, err)
	}
	return fmt.Errorf("%w after %s without progress (%v)", ErrOperationTimeout, timeout, err)
}

// cleanupContext bounds best-effort cleanup independently of the scan
// context, so resources are released even after an interruption.
func cleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), cleanupTimeout)
}

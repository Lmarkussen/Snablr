package smb

import (
	"context"
	"fmt"
	"time"
)

// releaseGracePeriod bounds the dial path, where the dialer owns the socket.
const releaseGracePeriod = 2 * time.Second

// phaseResult carries one bounded phase result back from its own goroutine.
type phaseResult[T any] struct {
	value T
	err   error
}

// bounded runs one SMB request phase under a hard wall-clock bound that the
// caller owns, and also aborts the phase when the share becomes terminal.
//
// Only the TCP connect has an OS level timeout; negotiate, session setup, tree
// connect, directory enumeration, stat, open and read all block on calls a
// wedged server can hold open indefinitely. The bound must therefore be
// enforced by the *caller*: the phase runs on its own goroutine and the caller
// returns as soon as the bound, the caller's context or the share's terminal
// state is reached, whatever the transport call is doing.
//
// The previous watchdog called the operation on the caller's goroutine and
// relied on invalidating the session to release it. That assumption does not
// hold for every blocking call inside the SMB dependency; a call that
// invalidation cannot release (for example the credit account's loan, which
// waits on a channel fed only by responses using a background context) held the
// worker, then the bounded job queue, then the share walker and therefore the
// whole target, with no bound at all. The caller-owned bound removes that
// class: a wedged call costs at most one phase bound.
func (c *Client) bounded(ctx context.Context, operation, share string, limit time.Duration, op func() error) error {
	if op == nil {
		return nil
	}
	_, err := runPhase(c, ctx, operation, share, limit, func() (struct{}, error) {
		return struct{}{}, op()
	})
	return err
}

// runPhase runs one bounded, share-scoped SMB request phase.
func runPhase[T any](c *Client, ctx context.Context, operation, share string, limit time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	if fn == nil {
		return zero, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = c.operationLimit()
	}
	// Cancellation wins immediately over any retry or recovery waiting.
	if err := ctx.Err(); err != nil {
		c.invalidate()
		return zero, err
	}
	abort := c.shareTerminal(share)
	if abort != nil {
		select {
		case <-abort:
			// The share is already terminal, so the phase is not even attempted.
			return zero, fmt.Errorf("%s: %w", operation, ErrShareUnhealthy)
		default:
		}
	}

	result := make(chan phaseResult[T], 1)
	go func() {
		value, err := fn()
		result <- phaseResult[T]{value: value, err: err}
	}()

	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case out := <-result:
		if err := ctx.Err(); err != nil && out.err != nil {
			return zero, err
		}
		return out.value, out.err
	case <-timer.C:
		// Prefer a phase that finished at the same instant so a healthy
		// boundary case is not reported as a timeout.
		select {
		case out := <-result:
			return out.value, out.err
		default:
		}
		c.notePhaseTimeout()
		c.invalidate()
		return zero, &operationTimeoutError{Operation: operation, Limit: limit}
	case <-ctx.Done():
		c.invalidate()
		return zero, ctx.Err()
	case <-abort:
		// The share reached a terminal state while this phase was in flight.
		// The connection state of the abandoned phase is unknown, so the session
		// is invalidated instead of being trusted again.
		c.invalidate()
		return zero, fmt.Errorf("%s: %w", operation, ErrShareUnhealthy)
	}
}

// notePhaseTimeout records one request phase abandoned by its bound.
func (c *Client) notePhaseTimeout() {
	c.mu.Lock()
	c.stats.OperationTimeouts++
	c.mu.Unlock()
}

// invalidate closes and clears the current session so any call blocked on the
// dead transport is released and the next operation reconnects. Closing is
// itself a network call, so it is detached: the caller never waits for a logoff
// the peer, or the dependency's transport mutex, may never answer.
func (c *Client) invalidate() {
	c.mu.Lock()
	session := c.session
	c.session = nil
	c.mu.Unlock()
	closeSessionAsync(session)
}

// closeSessionAsync closes a session on its own goroutine. A session close
// issues a logoff request and can contend with a wedged in-flight call, so no
// worker, walker or target completion may wait for it: the socket is closed
// regardless and the goroutine exits as soon as the transport lets it. A close
// that a transport never releases is therefore abandoned to its own goroutine
// instead of pinning the scanner.
func closeSessionAsync(session transportSession) {
	if session == nil {
		return
	}
	go func() { _ = session.Close() }()
}

// limitUntil caps one request phase by the remaining time before an absolute
// deadline. It lets a caller that owns a whole-operation budget reuse the
// per-phase watchdog without ever overshooting that budget.
func (c *Client) limitUntil(deadline time.Time) time.Duration {
	return c.limitBaseUntil(c.operationLimit(), deadline)
}

// limitBaseUntil caps an explicit per-phase bound by the remaining time before
// an absolute deadline. Read phases use the read idle timeout as their base, so
// a healthy slow transfer is not cut short by the shorter request-phase bound.
func (c *Client) limitBaseUntil(base time.Duration, deadline time.Time) time.Duration {
	limit := base
	if limit <= 0 {
		limit = c.operationLimit()
	}
	if deadline.IsZero() {
		return limit
	}
	remaining := time.Until(deadline)
	if remaining < limit {
		limit = remaining
	}
	if limit <= 0 {
		// The deadline is gone; a non-positive limit would restore the default,
		// so return the smallest bound that still expires immediately.
		return time.Nanosecond
	}
	return limit
}

// dialBounded establishes a session under a hard bound covering the TCP connect
// and the SMB handshake. The dialer receives a context that it must honour; the
// select below is a backstop that returns even if a dialer ignores it.
func (c *Client) dialBounded(ctx context.Context, dialAddr string, auth resolvedAuth) (transportSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	dialer := c.dialer
	dialTimeout := c.dialTimeout
	c.mu.Unlock()
	handshake := c.handshakeLimit()
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	total := dialTimeout + handshake + releaseGracePeriod

	dialCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	type outcome struct {
		session transportSession
		err     error
	}
	result := make(chan outcome, 1)
	go func() {
		session, err := dialer.Dial(dialCtx, dialAddr, auth, dialTimeout, handshake)
		result <- outcome{session: session, err: err}
	}()

	select {
	case out := <-result:
		if out.err != nil && out.session != nil {
			closeSessionAsync(out.session)
			out.session = nil
		}
		return out.session, out.err
	case <-dialCtx.Done():
		return nil, fmt.Errorf("%w: dial %s: %v", ErrReconnectTimeout, dialAddr, dialCtx.Err())
	}
}

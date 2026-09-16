package smb

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// releaseGracePeriod bounds the dial path, where the dialer owns the socket.
const releaseGracePeriod = 2 * time.Second

// bounded runs one SMB request phase under a hard wall-clock bound.
//
// Only the TCP connect has an OS level timeout; negotiate, session setup, tree
// connect, directory enumeration, stat, open and read all block on socket I/O
// that a wedged server can hold open indefinitely. On expiry the current
// session is invalidated (closed), which releases the blocked call exactly as a
// closed socket does, the phase is abandoned, and a timeout is returned.
// Callers treat that as a transport failure, discard any partial result, and
// retry under the recovery budget.
//
// The phase runs on the caller's goroutine and the bound is armed with a timer,
// so the healthy path costs no goroutine and no channel handoff per operation.
func (c *Client) bounded(ctx context.Context, operation string, limit time.Duration, op func() error) error {
	if op == nil {
		return nil
	}
	if limit <= 0 {
		limit = c.operationLimit()
	}

	var expired atomic.Bool
	timer := time.AfterFunc(limit, func() {
		expired.Store(true)
		c.mu.Lock()
		c.stats.OperationTimeouts++
		c.mu.Unlock()
		c.invalidate()
	})
	defer timer.Stop()

	// Cancellation releases the same blocked call as a timeout. context.AfterFunc
	// costs nothing until the context is actually cancelled.
	if ctx != nil && ctx.Done() != nil {
		stop := context.AfterFunc(ctx, c.invalidate)
		defer stop()
	}

	err := op()
	if expired.Load() {
		return &operationTimeoutError{Operation: operation, Limit: limit}
	}
	if ctx != nil && ctx.Err() != nil && err != nil {
		return ctx.Err()
	}
	return err
}

// invalidate closes and clears the current session so any call blocked on the
// dead transport is released and the next operation reconnects.
func (c *Client) invalidate() {
	c.mu.Lock()
	session := c.session
	c.session = nil
	c.mu.Unlock()
	if session != nil {
		_ = session.Close()
	}
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
			_ = out.session.Close()
			out.session = nil
		}
		return out.session, out.err
	case <-dialCtx.Done():
		return nil, fmt.Errorf("%w: dial %s: %v", ErrReconnectTimeout, dialAddr, dialCtx.Err())
	}
}

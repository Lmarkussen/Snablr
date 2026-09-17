package smb

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Transport health containment
//
// Per-operation bounds stop one SMB call from hanging, but they do not stop a
// whole target from spending its budget over and over: a share whose transport
// is wedged would otherwise make every one of its thousands of queued files
// consume the full per-operation recovery budget before failing. With the
// default 15 workers that is roughly fifteen files every two minutes, so a few
// hundred doomed files cost tens of minutes of wall clock.
//
// Containment therefore withholds work from a share once several of its
// operations have hit their hard bound with no successful read in between. The
// important property is that containment is *recoverable*: a transient
// transport problem must not permanently sacrifice the readable files that
// follow it. While a share is withheld, queued work waits instead of failing,
// and after a short cooldown exactly one probe is allowed through. A successful
// probe restores the share and the remaining queue continues; a failed probe
// re-arms the cooldown until the share's recovery budget is spent, at which
// point the share is abandoned for the rest of the target and queued work fails
// fast. That keeps both properties: no pathological runtime when a server is
// really broken, and no silent loss of recall when it is only briefly unwell.
//
// Only transport and session health is evidence. Ordinary SMB outcomes (access
// denied, not found, unsupported file, size limit) and content-parser failures
// never withhold a share.
const (
	// shareFailureStreakLimit is the number of *distinct* operations that may
	// hit their hard bound on one share, with no successful read in between,
	// before the share is withheld. Distinctness matters: one file retrying
	// three times must not condemn a share, because that retry reuses the same
	// operation identity.
	shareFailureStreakLimit = 3
	// defaultShareProbeCooldown is how long a withheld share waits before one
	// probe is allowed through. It is deliberately short so a transport that
	// recovered resumes work promptly.
	defaultShareProbeCooldown = 5 * time.Second
	// defaultShareRecoveryBudget is the cumulative time one share may spend
	// withheld on a single target. Once it is spent the share is abandoned, so
	// a permanently dead share is bounded while a transient problem of the same
	// length is fully recovered.
	defaultShareRecoveryBudget = 90 * time.Second
	// targetFailureFloor is the minimum number of consecutive transport
	// failures before the target-level recovery budget can abandon a target.
	targetFailureFloor = 6
	// targetShareFloor is the number of *distinct* shares that must have
	// contributed transport failures before the target itself can be abandoned.
	// One degraded share is handled by the share-level quarantine and must never
	// cost every other share of the target.
	targetShareFloor = 2
	// defaultTargetRecoveryBudget bounds wall-clock time spent in continuous
	// transport failure on one target with no successful read anywhere. A
	// healthy target completes reads far more often than this.
	defaultTargetRecoveryBudget = 2 * time.Minute
	// targetDialFailureLimit bounds consecutive failed reconnects. A server
	// that cannot be reconnected to is terminal for the target.
	targetDialFailureLimit = 2
)

var (
	// ErrShareUnhealthy reports that a share was abandoned after its recovery
	// budget was spent on repeated transport failures.
	ErrShareUnhealthy = errors.New("smb share marked unhealthy")
	// ErrTargetUnhealthy reports that a whole target was abandoned after
	// sustained transport failure across its shares with no progress.
	ErrTargetUnhealthy = errors.New("smb target marked unhealthy")
)

// shareHealth is the containment state for one share of one target.
type shareHealth struct {
	// failedOps records the distinct operations that hit their hard bound since
	// the last successful read on this share.
	failedOps map[string]struct{}
	// withheld is true while work is held back from this share.
	withheld bool
	// chargeFrom begins the quarantine interval not yet added to spent.
	chargeFrom time.Time
	// spent is the cumulative quarantine time charged to this share.
	spent time.Duration
	// nextProbeAt is the earliest time a probe may be granted.
	nextProbeAt time.Time
	// probing is true while one caller is running the probe, and probeDone is
	// closed when that probe resolves.
	probing   bool
	probeDone chan struct{}
	// abandoned is terminal for the rest of the target.
	abandoned bool
}

// probeOutcome is the terminal verdict of one granted share probe. Every
// outcome releases the lease and wakes the waiters; only a clean success
// restores the share, and only the failure outcomes re-arm the cooldown.
type probeOutcome int

const (
	// probeOutcomeCancelled releases the lease without a health verdict: the
	// caller's context ended, so the probe proved nothing about the share and
	// must not be read as either healthy or dead.
	probeOutcomeCancelled probeOutcome = iota
	// probeOutcomeSuccess is a probe that completed real work against the
	// share, which restores it and resumes the withheld queue.
	probeOutcomeSuccess
	// probeOutcomeTransportFailure is a probe whose operation failed with
	// transport evidence (hard phase bound or reconnectable error).
	probeOutcomeTransportFailure
	// probeOutcomeSessionUnavailable is a probe that never reached the network
	// because no session could be obtained.
	probeOutcomeSessionUnavailable
	// probeOutcomeBudgetExhausted is a probe whose owner ran out of its
	// per-operation recovery budget before it could attempt the network work.
	probeOutcomeBudgetExhausted
	// probeOutcomeProbeFailed is a probe that ran but did not demonstrate a
	// healthy share (for example an ordinary SMB status). Like every other
	// non-success outcome it keeps the share withheld and re-arms the cooldown.
	probeOutcomeProbeFailed
)

// probeLease is the exclusive right to run one share-recovery probe. It is
// created together with probing=true, and it is the only way to reach the
// terminal transition that clears probing and wakes the waiters.
//
// The lease is self-cleaning: resolution is idempotent and safe to call from a
// deferred function, so every ordinary return path after the grant — including
// budget exhaustion, session failure and a panic — still releases it. A lease
// that is never explicitly resolved by its owner is released by the deferred
// safety net as a cancellation, never as a health verdict.
type probeLease struct {
	client *Client
	share  string
	once   sync.Once
}

// Resolve performs the one terminal transition for this lease. It is
// idempotent: the first call wins and later calls (including the deferred
// safety net) are no-ops.
func (l *probeLease) Resolve(outcome probeOutcome) {
	if l == nil {
		return
	}
	l.once.Do(func() { l.client.resolveShareProbe(l.share, outcome) })
}

// healthState is the transport-health evidence for one target client.
type healthState struct {
	shares map[string]*shareHealth

	// transportFailures counts consecutive transport failures with no
	// successful read in between. failureShares records which shares produced
	// them and lastSuccess is the last substantive success.
	transportFailures int
	failureShares     map[string]struct{}
	lastSuccess       time.Time

	// dialFailures counts consecutive failed reconnects with no success.
	dialFailures int

	targetUnhealthy bool
}

// initHealthLocked prepares the containment maps. Callers hold c.mu.
func (c *Client) initHealthLocked() {
	if c.health.shares == nil {
		c.health.shares = make(map[string]*shareHealth)
	}
}

func (c *Client) shareHealthLocked(share string) *shareHealth {
	c.initHealthLocked()
	st := c.health.shares[share]
	if st == nil {
		st = &shareHealth{}
		c.health.shares[share] = st
	}
	return st
}

func (c *Client) probeCooldownLocked() time.Duration {
	if c.shareProbeCooldown > 0 {
		return c.shareProbeCooldown
	}
	return defaultShareProbeCooldown
}

func (c *Client) shareRecoveryLimitLocked() time.Duration {
	if c.shareRecoveryBudget > 0 {
		return c.shareRecoveryBudget
	}
	return defaultShareRecoveryBudget
}

// shareBudgetSpentLocked reports whether this share has used up its cumulative
// quarantine budget and must be abandoned.
func (c *Client) shareBudgetSpentLocked(st *shareHealth, now time.Time) bool {
	return c.shareSpentLocked(st, now) >= c.shareRecoveryLimitLocked()
}

// shareSpentLocked is the cumulative quarantine time charged to one share,
// including the interval that is still running.
func (c *Client) shareSpentLocked(st *shareHealth, now time.Time) time.Duration {
	spent := st.spent
	if !st.chargeFrom.IsZero() {
		spent += now.Sub(st.chargeFrom)
	}
	return spent
}

// withholdDeadlineLocked is the absolute time at which the share's remaining
// recovery budget is exhausted. It is the hard watchdog for the withheld and
// probing state: no waiter may block past it, whatever the probe owner does.
func (c *Client) withholdDeadlineLocked(st *shareHealth, now time.Time) time.Time {
	remaining := c.shareRecoveryLimitLocked() - c.shareSpentLocked(st, now)
	if remaining <= 0 {
		return now
	}
	base := st.chargeFrom
	if base.IsZero() {
		base = now
	}
	return base.Add(remaining)
}

// shareWaitLocked decides how long a waiter blocks before it re-examines the
// share. Nothing here may produce a zero-duration wait while the share is still
// withheld: a zero wait would spin the waiter on a timer instead of parking it.
//
//   - While a probe is in flight, nextProbeAt is irrelevant. Waiters park on the
//     probe completion channel, cancellation, or the withheld hard deadline.
//   - While no probe is in flight, the earlier of the probe cooldown and the
//     hard deadline applies.
func (c *Client) shareWaitLocked(st *shareHealth, now time.Time) (done <-chan struct{}, wait time.Duration) {
	done = st.probeDone
	wait = c.withholdDeadlineLocked(st, now).Sub(now)
	if !st.probing {
		if probeWait := st.nextProbeAt.Sub(now); probeWait < wait {
			wait = probeWait
		}
	}
	if wait < 0 {
		wait = 0
	}
	return done, wait
}

// acquireShareProbe holds queued work while a share is withheld and grants at
// most one probe per cooldown. A non-nil lease means the caller owns the probe
// and must resolve it with probeLease.Resolve; the caller must also be able to
// release it on every return path (a deferred Resolve does that structurally).
//
// Waiting rather than failing is what preserves recall: a file that is only
// delayed by a transient transport problem is still read once the probe
// restores the share.
func (c *Client) acquireShareProbe(ctx context.Context, share string) (lease *probeLease, waited bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		c.mu.Lock()
		if c.health.targetUnhealthy {
			c.mu.Unlock()
			return nil, waited, ErrTargetUnhealthy
		}
		if share == "" {
			c.mu.Unlock()
			return nil, waited, nil
		}
		c.initHealthLocked()
		st := c.health.shares[share]
		if st == nil || (!st.withheld && !st.abandoned) {
			c.mu.Unlock()
			return nil, waited, nil
		}
		now := time.Now()
		if st.abandoned || c.shareBudgetSpentLocked(st, now) {
			report := c.abandonShareLocked(share, ErrShareUnhealthy)
			c.mu.Unlock()
			report()
			return nil, waited, ErrShareUnhealthy
		}
		waited = true
		if !st.probing && !now.Before(st.nextProbeAt) {
			st.probing = true
			st.probeDone = make(chan struct{})
			lease := &probeLease{client: c, share: share}
			c.mu.Unlock()
			return lease, waited, nil
		}
		done, wait := c.shareWaitLocked(st, now)
		c.mu.Unlock()
		if err := waitUntil(ctx, wait, done); err != nil {
			return nil, waited, err
		}
	}
}

// waitShareReady blocks until a withheld share is restored or abandoned. It
// never claims the probe: the walker uses it so a directory listing is never
// what decides a share's health, and a failed listing cannot abort the walk.
func (c *Client) waitShareReady(ctx context.Context, share string) error {
	if share == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		c.mu.Lock()
		if c.health.targetUnhealthy {
			c.mu.Unlock()
			return ErrTargetUnhealthy
		}
		c.initHealthLocked()
		st := c.health.shares[share]
		if st == nil || (!st.withheld && !st.abandoned) {
			c.mu.Unlock()
			return nil
		}
		now := time.Now()
		if st.abandoned || c.shareBudgetSpentLocked(st, now) {
			report := c.abandonShareLocked(share, ErrShareUnhealthy)
			c.mu.Unlock()
			report()
			return ErrShareUnhealthy
		}
		done, wait := c.shareWaitLocked(st, now)
		c.mu.Unlock()
		if err := waitUntil(ctx, wait, done); err != nil {
			return err
		}
	}
}

// abandonShareLocked marks a share terminally abandoned and returns a function
// that emits the single representative coverage failure. Callers hold c.mu and
// must invoke the returned function after unlocking. A no-op is returned when
// the share was already abandoned, so exactly one record is emitted per share.
func (c *Client) abandonShareLocked(share string, err error) func() {
	st := c.health.shares[share]
	if st == nil || st.abandoned {
		return func() {}
	}
	st.abandoned = true
	st.withheld = false
	// Abandonment is a terminal transition for the withheld state, so any probe
	// owner still running is released and every waiter parked on the probe is
	// woken. The owner's own Resolve then finds probing already cleared and
	// becomes a no-op.
	releaseProbeLocked(st)
	c.stats.SharesAbandoned++
	handler := c.onFailure
	serverName := c.serverName
	if handler == nil {
		return func() {}
	}
	return func() {
		handler(OperationFailure{
			Operation:          "share abandoned",
			Share:              share,
			Server:             serverName,
			Category:           CategoryTransport,
			Attempts:           1,
			ReconnectAttempted: true,
			Err:                err,
		})
	}
}

// waitUntil waits for a probe resolution, a timer, or cancellation.
func waitUntil(ctx context.Context, wait time.Duration, done <-chan struct{}) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if done == nil {
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-done:
		return nil
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseProbeLocked clears the probed-in-flight state and wakes every waiter
// parked on the probe completion channel. Callers hold c.mu. It must only be
// used together with a terminal transition of the withheld state.
func releaseProbeLocked(st *shareHealth) {
	st.probing = false
	if done := st.probeDone; done != nil {
		st.probeDone = nil
		close(done)
	}
}

// resolveShareProbe records the outcome of a granted probe. Every outcome
// clears probing and wakes the waiters; a success also restores the share so the
// remaining queue continues, and a failure re-arms the cooldown.
func (c *Client) resolveShareProbe(share string, outcome probeOutcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil || !st.probing {
		// Already released by an earlier terminal transition (for example the
		// withheld watchdog abandoning the share while the probe was running).
		return
	}
	now := time.Now()
	if !st.chargeFrom.IsZero() {
		st.spent += now.Sub(st.chargeFrom)
	}
	st.chargeFrom = now
	switch outcome {
	case probeOutcomeSuccess:
		releaseProbeLocked(st)
		st.withheld = false
		st.failedOps = nil
		st.chargeFrom = time.Time{}
		st.nextProbeAt = time.Time{}
	default:
		releaseProbeLocked(st)
		st.nextProbeAt = now.Add(c.probeCooldownLocked())
	}
}

// healthBlocked reports the non-blocking terminal state of a share or target.
func (c *Client) healthBlocked(share string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health.targetUnhealthy {
		return ErrTargetUnhealthy
	}
	if share == "" {
		return nil
	}
	st := c.health.shares[share]
	if st != nil && st.abandoned {
		return ErrShareUnhealthy
	}
	return nil
}

// noteSuccess records a successful operation. progress must be true only for a
// substantive operation (an actual read); cheap plumbing such as a tree connect
// succeeds even on an unwell share, so it must not clear the recovery clock or
// a degraded share could keep a target alive forever.
func (c *Client) noteSuccess(share string, progress bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.dialFailures = 0
	if !progress {
		return
	}
	c.health.transportFailures = 0
	c.health.failureShares = nil
	c.health.lastSuccess = time.Now()
	if share == "" {
		return
	}
	if st := c.health.shares[share]; st != nil {
		st.failedOps = nil
		st.withheld = false
		st.chargeFrom = time.Time{}
		st.nextProbeAt = time.Time{}
		// A substantive success is proof the share is healthy even while a probe
		// is outstanding, so the probe's waiters are released instead of being
		// parked until the watchdog. The owner's own Resolve then becomes a
		// no-op, because probing has already been cleared.
		releaseProbeLocked(st)
	}
}

// noteHardTimeout records a distinct operation that consumed its full hard
// bound. It returns true only for the call that withholds the share, so the
// caller emits exactly one representative failure record.
func (c *Client) noteHardTimeout(share, operation string) (justWithheld bool) {
	if share == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.shareHealthLocked(share)
	if st.abandoned || st.withheld {
		// Already contained: this worker's failure is not new evidence.
		return false
	}
	if st.failedOps == nil {
		st.failedOps = make(map[string]struct{})
	}
	st.failedOps[operation] = struct{}{}
	if len(st.failedOps) < shareFailureStreakLimit {
		return false
	}
	now := time.Now()
	st.withheld = true
	st.chargeFrom = now
	st.nextProbeAt = now.Add(c.probeCooldownLocked())
	c.stats.SharesWithheld++
	return true
}

// noteTransportFailure records one transport-class failure for the target
// streak and returns true only for the call that abandons the target.
func (c *Client) noteTransportFailure(share string) (justAbandoned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.transportFailures++
	if share != "" {
		if c.health.failureShares == nil {
			c.health.failureShares = make(map[string]struct{})
		}
		c.health.failureShares[share] = struct{}{}
	}
	if c.health.targetUnhealthy {
		return false
	}
	budget := c.targetRecoveryBudget
	if budget <= 0 {
		budget = defaultTargetRecoveryBudget
	}
	// A target is only unhealthy when transport failure is sustained *and*
	// spread across more than one share: a single degraded share is handled by
	// the share-level quarantine and must not cost the rest of the target.
	if c.health.transportFailures >= targetFailureFloor &&
		len(c.health.failureShares) >= targetShareFloor &&
		time.Since(c.health.lastSuccess) >= budget {
		c.health.targetUnhealthy = true
		return true
	}
	return false
}

// noteDialFailure records a failed reconnect and returns true only for the call
// that abandons the target.
func (c *Client) noteDialFailure() (justAbandoned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health.targetUnhealthy {
		return false
	}
	c.health.dialFailures++
	if c.health.dialFailures >= targetDialFailureLimit {
		c.health.targetUnhealthy = true
		return true
	}
	return false
}

// targetUnhealthy reports whether the target has been abandoned.
func (c *Client) targetUnhealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health.targetUnhealthy
}

// healthSnapshot summarises containment state for diagnostics: shares that are
// currently withheld or abandoned, whether the target was abandoned, and the
// current transport failure streak.
func (c *Client) healthSnapshot() (containedShares int, targetUnhealthy bool, transportFailures int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.health.shares {
		if st.withheld || st.abandoned {
			containedShares++
		}
	}
	return containedShares, c.health.targetUnhealthy, c.health.transportFailures
}

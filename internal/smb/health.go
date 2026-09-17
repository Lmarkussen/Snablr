package smb

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Share containment
//
// Per-operation bounds stop one SMB call from hanging, but they do not stop a
// whole target from spending its budget over and over: a share whose transport
// is wedged would otherwise make every one of its thousands of queued files
// consume the full per-operation recovery budget before failing. With the
// default 15 workers that is roughly fifteen files every two minutes, so a few
// hundred doomed files cost tens of minutes of wall clock.
//
// Containment therefore holds work back from a share once several of its
// operations have hit their hard bound with no successful read in between. The
// important property is that containment is *recoverable*: a transient
// transport problem must not permanently sacrifice the readable files that
// follow it. While a share is degraded, queued work waits instead of failing,
// and after a short cooldown exactly one probe is allowed through. A successful
// probe restores the share and the remaining queue continues; a failed probe
// re-arms the cooldown until the share's recovery budget is spent, at which
// point the share is abandoned for the rest of the target and queued work fails
// fast. That keeps both properties: no pathological runtime when a server is
// really broken, and no silent loss of recall when it is only briefly unwell.
//
// The state machine is deliberately small and explicit:
//
//	healthy --(shareFailureStreakLimit distinct hard-bound operations)--> degraded
//	degraded --(probe or ordinary read succeeds)-------------------------> healthy
//	degraded --(recoverBy reached)---------------------------------------> abandoned
//	abandoned is terminal for the rest of the target
//
// Every state has a bounded exit: degraded always carries the absolute instant
// recoverBy at which any observer abandons the share, and every waiter selects
// on the state-change channel, the caller's context and recoverBy. Nothing in
// the containment path waits for another goroutine or a network call to finish
// without a deadline of its own.
//
// Only transport and session health is evidence. Ordinary SMB outcomes (access
// denied, not found, unsupported file, size limit) and content-parser failures
// never degrade a share.
const (
	// shareFailureStreakLimit is the number of *distinct* operations that may
	// hit their hard bound on one share, with no successful read in between,
	// before the share is degraded. Distinctness matters: one file retrying
	// three times must not condemn a share, because that retry reuses the same
	// operation identity.
	shareFailureStreakLimit = 3
	// defaultShareProbeCooldown is how long a degraded share waits before one
	// probe is allowed through. It is deliberately short so a transport that
	// recovered resumes work promptly.
	defaultShareProbeCooldown = 5 * time.Second
	// defaultShareRecoveryBudget is the absolute time one degraded episode may
	// last, and the cumulative time one share may spend degraded on a single
	// target. Once it is spent the share is abandoned. A transient problem of
	// the same length is still fully recovered, and detection is bounded
	// separately by the per-operation recovery budget.
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
	// containmentMinWait is the floor for one containment wait. Waits are
	// derived from absolute instants and are positive by construction; the floor
	// exists only so an unexpected non-positive value parks the waiter instead
	// of spinning on a zero-duration timer.
	containmentMinWait = 10 * time.Millisecond
)

var (
	// ErrShareUnhealthy reports that a share was abandoned after its recovery
	// budget was spent on repeated transport failures.
	ErrShareUnhealthy = errors.New("smb share marked unhealthy")
	// ErrTargetUnhealthy reports that a whole target was abandoned after
	// sustained transport failure across its shares with no progress.
	ErrTargetUnhealthy = errors.New("smb target marked unhealthy")
)

// sharePhase is the explicit containment state of one share of one target.
type sharePhase uint8

const (
	// shareHealthy admits normal work.
	shareHealthy sharePhase = iota
	// shareDegraded holds new expensive work back and allows exactly one probe
	// owner at a time. It always carries an absolute recoverBy instant.
	shareDegraded
	// shareAbandoned is terminal for the rest of the target.
	shareAbandoned
)

// shareHealth is the containment state for one share of one target.
type shareHealth struct {
	// failedOps records the distinct operations that hit their hard bound since
	// the last successful read on this share.
	failedOps map[string]struct{}
	// phase is the single source of truth for containment.
	phase sharePhase
	// spent is the cumulative degraded time charged to this share on this
	// target, including the episode currently in progress.
	spent time.Duration
	// degradedAt begins the episode in progress; recoverBy is the absolute
	// instant by which that episode must end in a healthy or abandoned state.
	// Both are fixed for the whole episode, so no waiter can ever observe a
	// deadline that moves.
	degradedAt time.Time
	recoverBy  time.Time
	// nextProbeAt is the earliest time a probe may be granted.
	nextProbeAt time.Time
	// probing is true while exactly one caller owns the probe.
	probing bool
	// change is closed and replaced on every observable transition so waiters
	// park on a condition instead of polling.
	change chan struct{}
	// terminal is closed exactly once, when the share becomes abandoned. Every
	// in-flight bounded phase of the share selects on it so a terminal share
	// decision also unblocks work that is already inside a transport call.
	terminal chan struct{}
	// waits counts containment parking iterations. It exists so tests can prove
	// waiters park instead of spinning.
	waits int64
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
	// share, which restores it and resumes the degraded queue.
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
	// non-success outcome it keeps the share degraded and re-arms the cooldown.
	probeOutcomeProbeFailed
)

// probeLease is the exclusive right to run one share-recovery probe. It is
// created together with probing=true, and it is the only way to reach the
// terminal transition that clears probing and wakes the waiters.
//
// The lease is self-cleaning: resolution is idempotent and safe to call from a
// deferred function, so every ordinary return path after the grant, including
// budget exhaustion, session failure and a panic, still releases it. A lease
// that is never explicitly resolved by its owner is released by the deferred
// safety net as a cancellation, never as a health verdict.
type probeLease struct {
	client *Client
	share  string
	once   sync.Once
}

// Resolve performs the one terminal transition for this lease. It is
// idempotent: the first call wins and later calls, including the deferred
// safety net, are no-ops.
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

// shareHealthLocked returns the containment state for a share, creating it
// healthy and ready to be waited on. Callers hold c.mu.
func (c *Client) shareHealthLocked(share string) *shareHealth {
	c.initHealthLocked()
	st := c.health.shares[share]
	if st == nil {
		st = &shareHealth{change: make(chan struct{})}
		c.health.shares[share] = st
	}
	if st.change == nil {
		st.change = make(chan struct{})
	}
	return st
}

// shareTerminal reports the channel that is closed when a share is abandoned.
// Every bounded phase of that share selects on it, so the terminal share
// decision unblocks work that is already inside a wedged transport call instead
// of waiting for the call's own bound. It returns nil for a target-wide or
// unknown share.
func (c *Client) shareTerminal(share string) <-chan struct{} {
	if share == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The state entry is created eagerly so every phase in flight for this
	// share observes the same channel that abandonment will close.
	st := c.shareHealthLocked(share)
	if st.terminal == nil {
		st.terminal = make(chan struct{})
		if st.phase == shareAbandoned {
			close(st.terminal)
		}
	}
	return st.terminal
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

// wakeLocked closes the current state-change channel and installs a fresh one,
// so every waiter parked on the previous channel re-examines the state. The
// channel is replaced immediately after closing, which makes a double close
// impossible. Callers hold c.mu.
func (c *Client) wakeLocked(st *shareHealth) {
	if st.change == nil {
		st.change = make(chan struct{})
		return
	}
	close(st.change)
	st.change = make(chan struct{})
}

// degradeShareLocked moves a share into the degraded phase and fixes the
// absolute instant by which it must recover. The window is measured from the
// moment the share is degraded, so a streak that took several bounded
// operations to detect can never eat into the recovery window and silently
// abandon a share that is still able to recover. It reports false when the
// share has already spent its cumulative recovery budget and must be abandoned
// instead. Callers hold c.mu.
func (c *Client) degradeShareLocked(st *shareHealth, now time.Time) bool {
	remaining := c.shareRecoveryLimitLocked() - st.spent
	if remaining < containmentMinWait {
		return false
	}
	st.phase = shareDegraded
	st.degradedAt = now
	st.recoverBy = now.Add(remaining)
	st.nextProbeAt = now.Add(c.probeCooldownLocked())
	c.wakeLocked(st)
	return true
}

// recoverShareLocked returns a degraded share to healthy, charging the episode
// that just ended to the share's cumulative recovery time. A success is proof
// the share is healthy even while a probe is outstanding, so the probe owner's
// later Resolve becomes a no-op. Callers hold c.mu.
func (c *Client) recoverShareLocked(st *shareHealth, now time.Time) {
	if !st.degradedAt.IsZero() {
		st.spent += now.Sub(st.degradedAt)
	}
	st.phase = shareHealthy
	st.degradedAt = time.Time{}
	st.recoverBy = time.Time{}
	st.nextProbeAt = time.Time{}
	st.failedOps = nil
	st.probing = false
	c.wakeLocked(st)
}

// shareWaitLocked reports how long a waiter parks before re-examining a
// degraded share. The result is positive by construction: the caller only
// reaches this point while the share is still degraded and inside its recovery
// window, so the recovery deadline is in the future, and either a probe is in
// flight (wait for its resolution or the deadline) or the probe cooldown is in
// the future. Nothing here may produce a zero-duration wait.
//
// Callers hold c.mu.
func (c *Client) shareWaitLocked(st *shareHealth, now time.Time) (<-chan struct{}, time.Duration) {
	wait := st.recoverBy.Sub(now)
	if !st.probing {
		if probeWait := st.nextProbeAt.Sub(now); probeWait < wait {
			wait = probeWait
		}
	}
	if wait < containmentMinWait {
		wait = containmentMinWait
	}
	return st.change, wait
}

// acquireShareProbe holds queued work while a share is degraded and grants at
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
		st := c.health.shares[share]
		if st == nil || st.phase == shareHealthy {
			c.mu.Unlock()
			return nil, waited, nil
		}
		now := time.Now()
		if st.phase == shareAbandoned {
			c.mu.Unlock()
			return nil, waited, ErrShareUnhealthy
		}
		if !now.Before(st.recoverBy) {
			report := c.abandonShareLocked(share, ErrShareUnhealthy)
			c.mu.Unlock()
			report()
			return nil, waited, ErrShareUnhealthy
		}
		waited = true
		st.waits++
		if !st.probing && !now.Before(st.nextProbeAt) {
			st.probing = true
			lease := &probeLease{client: c, share: share}
			c.mu.Unlock()
			return lease, waited, nil
		}
		change, wait := c.shareWaitLocked(st, now)
		c.mu.Unlock()
		if err := waitUntil(ctx, wait, change); err != nil {
			return nil, waited, err
		}
	}
}

// waitShareReady blocks until a degraded share is restored or abandoned. It
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
		st := c.health.shares[share]
		if st == nil || st.phase == shareHealthy {
			c.mu.Unlock()
			return nil
		}
		now := time.Now()
		if st.phase == shareAbandoned {
			c.mu.Unlock()
			return ErrShareUnhealthy
		}
		if !now.Before(st.recoverBy) {
			report := c.abandonShareLocked(share, ErrShareUnhealthy)
			c.mu.Unlock()
			report()
			return ErrShareUnhealthy
		}
		st.waits++
		change, wait := c.shareWaitLocked(st, now)
		c.mu.Unlock()
		if err := waitUntil(ctx, wait, change); err != nil {
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
	if st == nil || st.phase == shareAbandoned {
		return func() {}
	}
	now := time.Now()
	if !st.degradedAt.IsZero() {
		st.spent += now.Sub(st.degradedAt)
	}
	st.phase = shareAbandoned
	st.degradedAt = time.Time{}
	st.recoverBy = time.Time{}
	st.nextProbeAt = time.Time{}
	// Abandonment is terminal for the degraded state, so any probe owner still
	// running is released and every waiter parked on the state channel is woken.
	// The owner's own Resolve then finds probing already cleared and is a no-op.
	st.probing = false
	if st.terminal == nil {
		st.terminal = make(chan struct{})
	}
	close(st.terminal)
	c.wakeLocked(st)
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

// waitUntil waits for a state change, a timer, or cancellation.
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

// resolveShareProbe records the outcome of a granted probe. Every outcome
// clears probing and wakes the waiters; a success also restores the share so the
// remaining queue continues, and a failure re-arms the cooldown.
func (c *Client) resolveShareProbe(share string, outcome probeOutcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil || !st.probing {
		// Already released by an earlier terminal transition (for example the
		// recovery deadline abandoning the share while the probe was running).
		return
	}
	st.probing = false
	if outcome == probeOutcomeSuccess {
		c.recoverShareLocked(st, time.Now())
		return
	}
	st.nextProbeAt = time.Now().Add(c.probeCooldownLocked())
	c.wakeLocked(st)
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
	if st := c.health.shares[share]; st != nil && st.phase == shareAbandoned {
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
	st := c.health.shares[share]
	if st == nil {
		return
	}
	if st.phase == shareDegraded {
		// A substantive success is proof the share is healthy, so the waiters are
		// released instead of being parked until the recovery deadline. The
		// episode that just ended is charged to the share's cumulative recovery
		// time, which is what stops repeated short faults from adding up to an
		// unbounded amount of wall clock.
		c.recoverShareLocked(st, time.Now())
	}
}

// noteHardTimeout records a distinct operation that consumed its full hard
// bound. It returns true only for the call that degrades the share, so the
// caller emits exactly one representative failure record.
func (c *Client) noteHardTimeout(share, operation string) (justDegraded bool) {
	if share == "" {
		return false
	}
	c.mu.Lock()
	st := c.shareHealthLocked(share)
	if st.phase != shareHealthy {
		// Already contained: this worker's failure is not new evidence.
		c.mu.Unlock()
		return false
	}
	if st.failedOps == nil {
		st.failedOps = make(map[string]struct{})
	}
	st.failedOps[operation] = struct{}{}
	if len(st.failedOps) < shareFailureStreakLimit {
		c.mu.Unlock()
		return false
	}
	if !c.degradeShareLocked(st, time.Now()) {
		// The cumulative recovery budget was already spent: the share is out of
		// recovery allowance and becomes terminal now.
		report := c.abandonShareLocked(share, ErrShareUnhealthy)
		c.mu.Unlock()
		report()
		return false
	}
	c.stats.SharesWithheld++
	c.mu.Unlock()
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
// not healthy, whether the target was abandoned, and the current transport
// failure streak.
func (c *Client) healthSnapshot() (containedShares int, targetUnhealthy bool, transportFailures int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.health.shares {
		if st.phase != shareHealthy {
			containedShares++
		}
	}
	return containedShares, c.health.targetUnhealthy, c.health.transportFailures
}

// containmentWaitIterations reports how many times containment waiters
// re-examined a share. A small count proves waiters park on the state-change
// channel instead of spinning on zero-duration timers.
func (c *Client) containmentWaitIterations(share string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil {
		return 0
	}
	return st.waits
}

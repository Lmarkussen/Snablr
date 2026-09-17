package smb

import (
	"context"
	"errors"
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
	spent := st.spent
	if !st.chargeFrom.IsZero() {
		spent += now.Sub(st.chargeFrom)
	}
	return spent >= c.shareRecoveryLimitLocked()
}

// awaitShare holds queued work while a share is withheld and grants exactly one
// probe per cooldown. It returns probe=true when the caller has been granted the
// probe and must report the outcome with resolveShareProbe.
//
// Waiting rather than failing is what preserves recall: a file that is only
// delayed by a transient transport problem is still read once the probe
// restores the share.
func (c *Client) awaitShare(ctx context.Context, share string) (probe bool, waited bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		c.mu.Lock()
		if c.health.targetUnhealthy {
			c.mu.Unlock()
			return false, waited, ErrTargetUnhealthy
		}
		if share == "" {
			c.mu.Unlock()
			return false, waited, nil
		}
		c.initHealthLocked()
		st := c.health.shares[share]
		if st == nil || (!st.withheld && !st.abandoned) {
			c.mu.Unlock()
			return false, waited, nil
		}
		now := time.Now()
		if st.abandoned || c.shareBudgetSpentLocked(st, now) {
			report := c.abandonShareLocked(share, ErrShareUnhealthy)
			c.mu.Unlock()
			report()
			return false, waited, ErrShareUnhealthy
		}
		waited = true
		if !st.probing && !now.Before(st.nextProbeAt) {
			st.probing = true
			st.probeDone = make(chan struct{})
			c.mu.Unlock()
			return true, waited, nil
		}
		done := st.probeDone
		wait := st.nextProbeAt.Sub(now)
		c.mu.Unlock()
		if wait < 0 {
			wait = 0
		}
		if err := waitUntil(ctx, wait, done); err != nil {
			return false, waited, err
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
		done := st.probeDone
		wait := st.nextProbeAt.Sub(now)
		if done == nil && wait <= 0 {
			// No probe is in flight; wait briefly for one of the queued
			// workers to claim it instead of spinning.
			wait = 10 * time.Millisecond
		}
		c.mu.Unlock()
		if wait < 0 {
			wait = 0
		}
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

// resolveShareProbe records the outcome of a granted probe. A success restores
// the share so the remaining queue continues; a failure re-arms the cooldown.
func (c *Client) resolveShareProbe(share string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.health.shares[share]
	if st == nil || !st.probing {
		return
	}
	now := time.Now()
	if !st.chargeFrom.IsZero() {
		st.spent += now.Sub(st.chargeFrom)
	}
	st.chargeFrom = now
	st.probing = false
	done := st.probeDone
	st.probeDone = nil
	if ok {
		st.withheld = false
		st.failedOps = nil
		st.chargeFrom = time.Time{}
		st.nextProbeAt = time.Time{}
	} else {
		st.nextProbeAt = now.Add(c.probeCooldownLocked())
	}
	if done != nil {
		close(done)
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

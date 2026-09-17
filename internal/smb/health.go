package smb

import (
	"errors"
	"time"
)

// Circuit breaker
//
// Per-operation bounds stop one SMB call from hanging, but they do not stop a
// whole target from spending its budget over and over: a share whose transport
// is wedged would otherwise make every one of its thousands of queued files
// consume the full per-operation recovery budget before failing. With the
// default 15 workers that is roughly fifteen files every two minutes, so a few
// hundred doomed files cost tens of minutes of wall clock.
//
// The breaker watches *transport and session health only*. Ordinary SMB
// outcomes (access denied, not found, unsupported file, size limit) and
// content-parser failures are never evidence that a share is unhealthy, so a
// share is never abandoned because some of its files are unreadable or
// uninteresting. Isolation is deliberate: an unhealthy share is abandoned on
// its own, and only sustained target-wide failure abandons the whole target, so
// one bad share cannot prevent a healthy share from being scanned.
const (
	// shareFailureStreakLimit is the number of *distinct* operations that may
	// hit their hard bound on one share, with no successful operation in
	// between, before the share is abandoned. Distinctness matters: one file
	// retrying three times must not condemn a share, because that retry reuses
	// the same operation identity.
	shareFailureStreakLimit = 3
	// targetFailureFloor is the minimum number of consecutive transport
	// failures before the target-level recovery budget can abandon a target.
	targetFailureFloor = 6
	// defaultTargetRecoveryBudget bounds wall-clock time spent in continuous
	// transport failure on one target with no successful operation anywhere.
	// A healthy target completes operations far more often than this, so
	// exceeding it means the target itself is unhealthy and the scan must move
	// on rather than burn the same budget on every remaining object.
	defaultTargetRecoveryBudget = 2 * time.Minute
	// targetDialFailureLimit bounds consecutive failed reconnects. A server
	// that cannot be reconnected to is terminal for the target.
	targetDialFailureLimit = 2
)

var (
	// ErrShareUnhealthy reports that a share was abandoned by the circuit
	// breaker after repeated transport/session failures on distinct objects.
	ErrShareUnhealthy = errors.New("smb share marked unhealthy")
	// ErrTargetUnhealthy reports that a whole target was abandoned by the
	// circuit breaker after sustained transport failure with no progress.
	ErrTargetUnhealthy = errors.New("smb target marked unhealthy")
)

// healthState is the transport-health evidence for one target client.
//
// The zero value is ready to use; the client initialises the maps.
type healthState struct {
	// failedOps records, per share, the distinct operations that consumed
	// their full hard bound. It is cleared whenever an operation on that share
	// succeeds.
	failedOps map[string]map[string]struct{}
	// unhealthy marks shares already abandoned.
	unhealthy map[string]bool

	// transportFailures counts consecutive transport failures with no
	// successful operation in between, and lastSuccess records the most recent
	// substantive success that reset the run.
	transportFailures int
	lastSuccess       time.Time

	// dialFailures counts consecutive failed reconnects with no success.
	dialFailures int

	targetUnhealthy bool
}

// initHealth prepares the breaker maps. Callers hold c.mu.
func (c *Client) initHealthLocked() {
	if c.health.failedOps == nil {
		c.health.failedOps = make(map[string]map[string]struct{})
	}
	if c.health.unhealthy == nil {
		c.health.unhealthy = make(map[string]bool)
	}
}

// healthBlocked reports whether the share or the target has already been
// abandoned. It is the fast path queued work takes so doomed objects fail
// without touching the network.
func (c *Client) healthBlocked(share string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health.targetUnhealthy {
		return ErrTargetUnhealthy
	}
	if share != "" && c.health.unhealthy[share] {
		return ErrShareUnhealthy
	}
	return nil
}

// noteSuccess records a successful operation. progress must be true only for a
// substantive operation (an actual read); cheap plumbing such as a tree connect
// succeeds even on a share whose every read fails, so it must not clear the
// target recovery clock or a wedged share could keep a target alive forever.
func (c *Client) noteSuccess(share string, progress bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.dialFailures = 0
	if !progress {
		return
	}
	c.health.transportFailures = 0
	c.health.lastSuccess = time.Now()
	if share != "" && c.health.failedOps != nil {
		delete(c.health.failedOps, share)
	}
}

// noteHardTimeout records a distinct operation that consumed its full hard
// bound. It returns true when this event abandoned the share.
func (c *Client) noteHardTimeout(share, operation string) (shareAbandoned bool) {
	if share == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initHealthLocked()
	if c.health.unhealthy[share] {
		return true
	}
	set := c.health.failedOps[share]
	if set == nil {
		set = make(map[string]struct{})
		c.health.failedOps[share] = set
	}
	set[operation] = struct{}{}
	if len(set) >= shareFailureStreakLimit {
		c.health.unhealthy[share] = true
		return true
	}
	return false
}

// noteTransportFailure records one transport-class failure for the target
// streak and returns true when the target recovery budget is exhausted.
func (c *Client) noteTransportFailure() (targetAbandoned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.health.transportFailures++
	if c.health.targetUnhealthy {
		return true
	}
	budget := c.targetRecoveryBudget
	if budget <= 0 {
		budget = defaultTargetRecoveryBudget
	}
	if c.health.transportFailures >= targetFailureFloor &&
		now.Sub(c.health.lastSuccess) >= budget {
		c.health.targetUnhealthy = true
		return true
	}
	return false
}

// noteDialFailure records a failed reconnect and returns true when the target
// is unreachable and must be abandoned.
func (c *Client) noteDialFailure() (targetAbandoned bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
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

// healthSnapshot returns a copy of the breaker state for diagnostics.
func (c *Client) healthSnapshot() (unhealthyShares int, targetUnhealthy bool, transportFailures int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, abandoned := range c.health.unhealthy {
		if abandoned {
			unhealthyShares++
		}
	}
	return unhealthyShares, c.health.targetUnhealthy, c.health.transportFailures
}

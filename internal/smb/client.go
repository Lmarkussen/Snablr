package smb

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
	"snablr/internal/smbkerberos"
)

const (
	defaultPort        = "445"
	defaultDialTimeout = 5 * time.Second
	defaultMaxDepth    = 64
	defaultMaxReadSize = 4 * 1024 * 1024
)

var (
	ErrNotConnected  = errors.New("smb client is not connected")
	ErrFileTooLarge  = errors.New("remote file exceeds configured read limit")
	ErrInvalidAuth   = errors.New("invalid SMB authentication configuration")
	ErrInvalidNTHash = errors.New("invalid NT hash")
)

type AuthMode string

const (
	AuthModePassword AuthMode = "password"
	AuthModeNTHash   AuthMode = "ntlm-hash"
	AuthModeKerberos AuthMode = "kerberos"
)

// Auth contains resolved SMB credentials. It is intentionally not serialized
// or formatted; callers must keep password and NT hash inputs distinct.
type Auth struct {
	Mode     AuthMode
	Username string
	Domain   string
	Password string
	NTHash   [16]byte
	CCache   string
	SPN      string
}

func NewPasswordAuth(username, domain, password string) Auth {
	return Auth{Mode: AuthModePassword, Username: username, Domain: domain, Password: password}
}

func NewNTHashAuth(username, domain, encodedHash string) (Auth, error) {
	hash, err := ParseNTHash(encodedHash)
	if err != nil {
		return Auth{}, err
	}
	return Auth{Mode: AuthModeNTHash, Username: username, Domain: domain, NTHash: hash}, nil
}

func NewKerberosAuth(username, domain, ccache, spn string) Auth {
	return Auth{Mode: AuthModeKerberos, Username: username, Domain: domain, CCache: ccache, SPN: spn}
}

func ParseNTHash(encoded string) ([16]byte, error) {
	var hash [16]byte
	if len(encoded) != 32 {
		return hash, fmt.Errorf("%w: expected 32 hexadecimal characters", ErrInvalidNTHash)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(hash) {
		return hash, fmt.Errorf("%w: expected 32 hexadecimal characters", ErrInvalidNTHash)
	}
	copy(hash[:], decoded)
	return hash, nil
}

type RemoteFile struct {
	Host       string
	Share      string
	Path       string
	Name       string
	Size       int64
	ModifiedAt time.Time
	IsDir      bool
	Extension  string
}

type ShareInfo struct {
	Name        string
	Description string
	Type        string
}

type SMBClient interface {
	Connect(host, user, pass string) error
	Close() error
	ListShares() ([]ShareInfo, error)
	WalkShare(share string, fn func(RemoteFile) error) error
	ReadFile(share, path string) ([]byte, error)
}

type Client struct {
	mu sync.Mutex

	host       string
	serverName string
	dialAddr   string
	auth       resolvedAuth

	dialTimeout time.Duration
	// handshakeTimeout bounds SMB negotiate plus session setup.
	handshakeTimeout time.Duration
	// operationTimeout bounds one SMB request phase.
	operationTimeout time.Duration
	// readIdleTimeout bounds the time between read progress.
	readIdleTimeout time.Duration
	// readTotalTimeout is the absolute bound on reading one object.
	readTotalTimeout time.Duration
	// reconnectWaitLimit is the hard cap on waiting for a coordinated reconnect.
	reconnectWaitLimit time.Duration
	// recoveryBudget is the hard cap on one operation including retries.
	recoveryBudget time.Duration
	// targetRecoveryBudget bounds continuous transport failure on one target.
	targetRecoveryBudget time.Duration
	maxDepth             int
	maxReadSize          int64

	dialer transportDialer

	session            transportSession
	recovering         bool
	recoverDone        chan struct{}
	lastFailedRecovery time.Time
	// authFailure records a terminal authentication failure. Until the operator
	// credential context changes, no further dial is attempted.
	authFailure error
	// lastRecoveryErr records why the last coordinated reconnect failed, so
	// waiters are released with the real cause instead of a stale success.
	lastRecoveryErr error

	onEvent   func(TransportEvent)
	onFailure func(OperationFailure)
	stats     TransportStats
	// health holds the circuit-breaker evidence for this target.
	health healthState
}

// resolvedAuth is the operator credential context resolved once at connect time
// and reused verbatim for every reconnect. It is never rendered: String and
// GoString redact it, and no log line includes it.
type resolvedAuth struct {
	mode     AuthMode
	username string
	domain   string
	password string
	ntHash   [16]byte
	ccache   string
	spn      string
}

func (a resolvedAuth) String() string   { return "smb<redacted>" }
func (a resolvedAuth) GoString() string { return "smb<redacted>" }

func (a resolvedAuth) initiator() (smb2.Initiator, error) {
	switch a.mode {
	case AuthModeKerberos:
		ccache, err := smbkerberos.ResolveCCache(a.ccache)
		if err != nil {
			return nil, err
		}
		return smbkerberos.NewFromCCache(ccache, smbkerberos.ResolveConfig(), a.spn)
	case AuthModeNTHash:
		initiator := &smb2.NTLMInitiator{User: a.username, Domain: a.domain}
		initiator.Hash = append([]byte(nil), a.ntHash[:]...)
		return initiator, nil
	case AuthModePassword:
		return &smb2.NTLMInitiator{User: a.username, Domain: a.domain, Password: a.password}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported SMB authentication mode %q", ErrInvalidAuth, a.mode)
	}
}

// String redacts the client so accidental formatting cannot leak credentials.
func (c *Client) String() string { return "smb.Client<redacted>" }

// GoString redacts the client for %#v formatting.
func (c *Client) GoString() string { return "smb.Client<redacted>" }

func NewClient() *Client {
	return &Client{
		dialTimeout:          defaultDialTimeout,
		handshakeTimeout:     defaultHandshakeTimeout,
		operationTimeout:     defaultOperationTimeout,
		readIdleTimeout:      defaultReadIdleTimeout,
		readTotalTimeout:     defaultReadTotalTimeout,
		reconnectWaitLimit:   defaultReconnectWaitLimit,
		recoveryBudget:       defaultRecoveryBudget,
		targetRecoveryBudget: defaultTargetRecoveryBudget,
		maxDepth:             defaultMaxDepth,
		maxReadSize:          defaultMaxReadSize,
		dialer:               smb2Dialer{},
		health:               healthState{lastSuccess: time.Now()},
	}
}

// SetOperationTimeout overrides the bound applied to one SMB request phase.
// Non-positive values restore the default.
func (c *Client) SetOperationTimeout(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.operationTimeout = defaultOperationTimeout
		return
	}
	c.operationTimeout = limit
}

// SetReadIdleTimeout overrides the bound between read progress. Non-positive
// values restore the default.
func (c *Client) SetReadIdleTimeout(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.readIdleTimeout = defaultReadIdleTimeout
		return
	}
	c.readIdleTimeout = limit
}

// SetReadTotalTimeout overrides the absolute bound on reading one object.
// Non-positive values restore the default.
func (c *Client) SetReadTotalTimeout(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.readTotalTimeout = defaultReadTotalTimeout
		return
	}
	c.readTotalTimeout = limit
}

// readTotalLimit reports the absolute bound on reading one object.
func (c *Client) readTotalLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readTotalTimeout <= 0 {
		return defaultReadTotalTimeout
	}
	return c.readTotalTimeout
}

// SetHandshakeTimeout overrides the bound on SMB negotiate plus session setup.
// Non-positive values restore the default.
func (c *Client) SetHandshakeTimeout(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.handshakeTimeout = defaultHandshakeTimeout
		return
	}
	c.handshakeTimeout = limit
}

// SetReconnectWaitLimit overrides the hard cap on waiting for a coordinated
// reconnect. Non-positive values restore the default.
func (c *Client) SetReconnectWaitLimit(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.reconnectWaitLimit = defaultReconnectWaitLimit
		return
	}
	c.reconnectWaitLimit = limit
}

// SetRecoveryBudget overrides the hard cap on one operation including every
// reconnect, backoff and retry. Non-positive values restore the default.
func (c *Client) SetRecoveryBudget(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.recoveryBudget = defaultRecoveryBudget
		return
	}
	c.recoveryBudget = limit
}

// SetTargetRecoveryBudget overrides the wall-clock bound on continuous
// transport failure on one target with no successful operation. Non-positive
// values restore the default.
func (c *Client) SetTargetRecoveryBudget(limit time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		c.targetRecoveryBudget = defaultTargetRecoveryBudget
		return
	}
	c.targetRecoveryBudget = limit
}

// Timeouts returns the effective bounded-timing configuration.
func (c *Client) Timeouts() (handshake, operation, readIdle, reconnectWait, recoveryBudget time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handshakeTimeout, c.operationTimeout, c.readIdleTimeout, c.reconnectWaitLimit, c.recoveryBudget
}

// operationLimit reports the effective bound for one request phase.
func (c *Client) operationLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operationTimeout <= 0 {
		return defaultOperationTimeout
	}
	return c.operationTimeout
}

// handshakeLimit reports the effective bound for negotiate plus session setup.
func (c *Client) handshakeLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handshakeTimeout <= 0 {
		return defaultHandshakeTimeout
	}
	return c.handshakeTimeout
}

// readLimit reports the effective bound between read progress.
func (c *Client) readLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readIdleTimeout <= 0 {
		return defaultReadIdleTimeout
	}
	return c.readIdleTimeout
}

// waitLimit reports the effective bound on waiting for a coordinated reconnect.
func (c *Client) waitLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reconnectWaitLimit <= 0 {
		return defaultReconnectWaitLimit
	}
	return c.reconnectWaitLimit
}

// budgetLimit reports the effective cap on one operation including retries.
func (c *Client) budgetLimit() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recoveryBudget <= 0 {
		return defaultRecoveryBudget
	}
	return c.recoveryBudget
}

// SetTransportEventHandler installs a structured transport lifecycle callback
// (reconnect attempts, restores, exhausted retries). Events never contain
// credential material.
func (c *Client) SetTransportEventHandler(handler func(TransportEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEvent = handler
}

// SetOperationFailureHandler installs a callback that receives one structured
// record per operation that ultimately failed (retry budget exhausted, or
// immediately for non-retryable failures such as access denied). Operations
// that recover after a reconnect are never reported.
func (c *Client) SetOperationFailureHandler(handler func(OperationFailure)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onFailure = handler
}

// TransportStats returns the run-local transport recovery accounting.
func (c *Client) TransportStats() TransportStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Client) SetMaxReadSize(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxReadSize = limit
}

func (c *Client) Connect(host, user, pass string) error {
	return c.ConnectWithAuth(host, NewPasswordAuth(user, "", pass))
}

func (c *Client) ConnectWithAuth(host string, auth Auth) error {
	serverName, dialAddr, err := splitHost(host)
	if err != nil {
		return err
	}

	parsedDomain, username := splitUser(auth.Username)
	if username == "" && auth.Mode != AuthModeKerberos {
		return fmt.Errorf("username cannot be empty")
	}
	domain := auth.Domain
	if parsedDomain != "" {
		domain = parsedDomain
	}
	if auth.Mode != AuthModePassword && auth.Mode != AuthModeNTHash && auth.Mode != AuthModeKerberos {
		return fmt.Errorf("%w: unsupported SMB authentication mode %q", ErrInvalidAuth, auth.Mode)
	}
	if auth.Mode == AuthModeNTHash && auth.Password != "" {
		return fmt.Errorf("%w: password cannot be supplied with NT hash authentication", ErrInvalidAuth)
	}
	if auth.Mode == AuthModeKerberos && (auth.Password != "" || auth.NTHash != [16]byte{}) {
		return fmt.Errorf("%w: password and NT hash cannot be supplied with SMB Kerberos authentication", ErrInvalidAuth)
	}

	if auth.Mode == AuthModeKerberos && strings.TrimSpace(auth.SPN) == "" {
		return fmt.Errorf("%w: SMB Kerberos requires a service principal", ErrInvalidAuth)
	}

	resolved := resolvedAuth{
		mode:     auth.Mode,
		username: username,
		domain:   domain,
		password: auth.Password,
		ntHash:   auth.NTHash,
		ccache:   auth.CCache,
		spn:      auth.SPN,
	}

	c.mu.Lock()
	previous := c.session
	c.session = nil
	c.host = host
	c.serverName = serverName
	c.dialAddr = dialAddr
	c.auth = resolved
	c.lastFailedRecovery = time.Time{}
	c.authFailure = nil
	c.lastRecoveryErr = nil
	// A connect establishes a fresh target context: clear any breaker evidence
	// from an earlier connection so a new target is not pre-condemned.
	c.health = healthState{lastSuccess: time.Now()}
	c.mu.Unlock()

	if previous != nil {
		_ = previous.Close()
	}

	session, err := c.dialBounded(context.Background(), dialAddr, resolved)
	if err != nil {
		if IsAuthFailure(err) {
			c.recordAuthFailure(err)
		}
		// Keep the resolved context so a later operation can retry the connect.
		return fmt.Errorf("dial %s: %w", dialAddr, err)
	}

	c.mu.Lock()
	c.session = session
	c.mu.Unlock()
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	session := c.session
	c.session = nil
	c.host = ""
	c.serverName = ""
	c.dialAddr = ""
	c.auth = resolvedAuth{}
	c.mu.Unlock()

	if session == nil {
		return nil
	}
	if err := session.Close(); err != nil && !isIgnorableCloseError(err) {
		return err
	}
	return nil
}

func isIgnorableCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// A logoff that hit its bound means the server stopped answering; the
	// socket is closed regardless, so the failed handshake is not an error
	// worth surfacing during shutdown.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "connection already closed")
}

// currentSession returns the live session. While another worker is recovering
// the transport it waits for that recovery instead of dialing again, which
// keeps one server failure to one reconnect.
func (c *Client) currentSession(ctx context.Context) (transportSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		c.mu.Lock()
		// A terminal authentication failure is not recoverable: fail fast
		// instead of dialling the same rejected credentials again.
		if c.authFailure != nil {
			err := c.authFailure
			c.mu.Unlock()
			return nil, err
		}
		if c.session != nil && !c.recovering {
			session := c.session
			c.mu.Unlock()
			return session, nil
		}
		if c.session == nil {
			// The transport may have been lost; re-establish it lazily when the
			// operator credential context is still known.
			if c.dialAddr == "" {
				c.mu.Unlock()
				return nil, ErrNotConnected
			}
			if !c.lastFailedRecovery.IsZero() && time.Since(c.lastFailedRecovery) < reconnectCooldown {
				c.mu.Unlock()
				return nil, fmt.Errorf("%w: reconnect cooldown active", ErrNotConnected)
			}
			c.mu.Unlock()
			if err := c.recover(ctx, nil); err != nil {
				return nil, err
			}
			continue
		}
		done := c.recoverDone
		wait := c.reconnectWaitLimit
		if wait <= 0 {
			wait = defaultReconnectWaitLimit
		}
		c.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-done:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			// The leader did not finish inside the wait bound. Waiting workers
			// are always released rather than blocked on a wedged reconnect.
			return nil, ErrReconnectTimeout
		}
	}
}

// recover reconnects the transport with the same operator credential context.
// It is coordinated: the first observer performs the reconnect, every other
// worker either waits for it or reuses the session it established.
func (c *Client) recover(ctx context.Context, used transportSession) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	if c.dialAddr == "" {
		c.mu.Unlock()
		return ErrNotConnected
	}
	if c.authFailure != nil {
		err := c.authFailure
		c.mu.Unlock()
		return err
	}
	if c.session != nil && used != nil && c.session != used {
		// Another worker already replaced the dead session.
		c.mu.Unlock()
		return nil
	}
	if c.recovering {
		done := c.recoverDone
		wait := c.reconnectWaitLimit
		if wait <= 0 {
			wait = defaultReconnectWaitLimit
		}
		c.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-done:
			timer.Stop()
			// Reuse the recovered session, or report why the leader failed.
			c.mu.Lock()
			authFailure := c.authFailure
			session := c.session
			recoveryErr := c.lastRecoveryErr
			c.mu.Unlock()
			switch {
			case authFailure != nil:
				return authFailure
			case session != nil:
				return nil
			case recoveryErr != nil:
				return recoveryErr
			default:
				return ErrNotConnected
			}
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			// Never leave a waiter blocked on a leader that cannot finish.
			return ErrReconnectTimeout
		}
	}
	if c.session == nil && !c.lastFailedRecovery.IsZero() && time.Since(c.lastFailedRecovery) < reconnectCooldown {
		c.mu.Unlock()
		return fmt.Errorf("%w: reconnect cooldown active", ErrNotConnected)
	}
	c.recovering = true
	c.recoverDone = make(chan struct{})
	done := c.recoverDone
	stale := c.session
	auth := c.auth
	dialAddr := c.dialAddr
	serverName := c.serverName
	c.stats.ReconnectsAttempted++
	c.mu.Unlock()

	if stale != nil {
		_ = stale.Close()
	}

	session, err := c.dialBounded(ctx, dialAddr, auth)

	c.mu.Lock()
	c.recovering = false
	if err != nil {
		c.stats.ReconnectsFailed++
		c.session = nil
		c.lastRecoveryErr = err
		if IsAuthFailure(err) {
			c.authFailure = fmt.Errorf("%w: %v", ErrAuthFailure, err)
			c.stats.AuthFailures++
		}
		c.lastFailedRecovery = time.Now()
		handler := c.onEvent
		close(done)
		c.mu.Unlock()
		emitTransportEvent(handler, TransportEvent{Kind: TransportEventRecoveryFailed, Server: serverName, Operation: "reconnect", Err: err})
		// A server that cannot be reconnected to is terminal for the target:
		// do not let every remaining share and file re-dial it in turn.
		if !IsAuthFailure(err) {
			if c.noteDialFailure() {
				c.reportAbandonment("", true, err)
			}
			if c.targetUnhealthy() {
				return fmt.Errorf("%w: reconnect to %s failed: %v", ErrTargetUnhealthy, serverName, err)
			}
		}
		return err
	}
	c.session = session
	c.lastRecoveryErr = nil
	c.stats.ReconnectsSucceeded++
	handler := c.onEvent
	close(done)
	c.mu.Unlock()
	emitTransportEvent(handler, TransportEvent{Kind: TransportEventRestored, Server: serverName, Operation: "reconnect"})
	return nil
}

func emitTransportEvent(handler func(TransportEvent), event TransportEvent) {
	if handler != nil {
		handler(event)
	}
}

// recordAuthFailure marks the credential context as rejected so no further dial
// is attempted until the operator supplies a new context.
func (c *Client) recordAuthFailure(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authFailure == nil {
		c.stats.AuthFailures++
	}
	c.authFailure = fmt.Errorf("%w: %v", ErrAuthFailure, err)
}

// runOperation executes one SMB operation with bounded transport recovery. The
// operation is retried from the beginning after a reconnect, so a file that hit
// the reset is re-read rather than skipped.
//
// share scopes the operation for the circuit breaker (empty for a target-level
// operation). The recovery budget is handed to fn as an absolute deadline, so a
// phase that keeps making tiny progress can no longer outlive the operation
// bound the way an indefinitely refreshed read timeout could.
//
// progress marks an operation whose success is real inspection progress and may
// therefore clear the target recovery clock.
func (c *Client) runOperation(ctx context.Context, operation, share string, progress bool, fn func(session transportSession, deadline time.Time) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	reconnectAttempted := false
	budgetDeadline := time.Now().Add(c.budgetLimit())
	for attempt := 0; attempt < totalOperationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Queued work for a share (or target) that has already been abandoned
		// fails immediately instead of consuming another recovery budget.
		if blocked := c.healthBlocked(share); blocked != nil {
			return blocked
		}
		if time.Now().After(budgetDeadline) {
			// The recovery budget for this operation is exhausted: record the
			// final failure and let the scan continue with the next object.
			c.mu.Lock()
			c.stats.RetryExhausted++
			handler := c.onEvent
			serverName := c.serverName
			c.mu.Unlock()
			emitTransportEvent(handler, TransportEvent{
				Kind: TransportEventRetryExhausted, Server: serverName, Operation: operation,
				Attempt: attempt + 1, MaxAttempts: totalOperationAttempts, Err: lastErr,
			})
			c.reportOperationFailure(operation, lastErr, attempt+1, reconnectAttempted)
			return fmt.Errorf("%s: %w", operation, lastErr)
		}
		session, err := c.currentSession(ctx)
		if err != nil {
			if IsAuthFailure(err) {
				c.reportOperationFailure(operation, err, attempt+1, reconnectAttempted)
			}
			return err
		}
		c.mu.Lock()
		c.stats.OperationAttempts++
		c.mu.Unlock()

		err = fn(session, budgetDeadline)
		if err == nil {
			c.mu.Lock()
			c.stats.OperationSuccesses++
			if attempt > 0 {
				c.stats.FilesRecovered += 1
			}
			c.mu.Unlock()
			c.noteSuccess(share, progress)
			return nil
		}
		c.mu.Lock()
		c.stats.OperationFailures++
		c.mu.Unlock()
		if IsAuthFailure(err) {
			// Authentication is terminal: no reconnect, no retry, no storm.
			c.recordAuthFailure(err)
			c.reportOperationFailure(operation, err, attempt+1, reconnectAttempted)
			return err
		}
		if !isRetryableOperation(err) || ctx.Err() != nil {
			// Non-retryable failures (access denied, not found, ...) are final
			// immediately and are reported once.
			c.reportOperationFailure(operation, err, attempt+1, reconnectAttempted)
			return err
		}
		lastErr = err
		// Circuit-breaker accounting. Only hard phase timeouts and recovery
		// failures are evidence that a share is unhealthy: an ordinary reset
		// that heals on the next attempt must not condemn a share, and a
		// cascade caused by another worker invalidating the shared session is
		// not independent evidence either.
		if isHardHealthFailure(err) {
			if c.noteHardTimeout(share, operation) {
				c.reportAbandonment(share, false, err)
			}
		}
		if IsReconnectable(err) {
			if c.noteTransportFailure() {
				c.reportAbandonment(share, true, err)
			}
		}
		// Whatever this worker's own failure meant, stop as soon as the share or
		// the target has been abandoned — including when another worker was the
		// one that detected it, so no doomed object keeps retrying.
		if blocked := c.healthBlocked(share); blocked != nil {
			return fmt.Errorf("%s: %w", operation, blocked)
		}
		if attempt+1 >= totalOperationAttempts {
			break
		}
		c.mu.Lock()
		c.stats.OperationsRetried++
		if IsReconnectable(err) {
			c.stats.TransportFailures++
		}
		handler := c.onEvent
		serverName := c.serverName
		c.mu.Unlock()

		if IsReconnectable(err) {
			reconnectAttempted = true
			emitTransportEvent(handler, TransportEvent{
				Kind: TransportEventRetrying, Server: serverName, Operation: operation,
				Attempt: attempt + 1, MaxAttempts: maxReconnectAttempts, Err: err,
			})
			if rerr := c.recover(ctx, session); rerr != nil {
				if errors.Is(rerr, ErrTargetUnhealthy) {
					return fmt.Errorf("%s: %w", operation, ErrTargetUnhealthy)
				}
				c.reportOperationFailure(operation, lastErr, attempt+1, reconnectAttempted)
				return fmt.Errorf("%s: %w", operation, lastErr)
			}
		}
		if err := sleepContext(ctx, reconnectBackoff); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.stats.RetryExhausted++
	handler := c.onEvent
	serverName := c.serverName
	c.mu.Unlock()
	emitTransportEvent(handler, TransportEvent{
		Kind: TransportEventRetryExhausted, Server: serverName, Operation: operation,
		Attempt: totalOperationAttempts, MaxAttempts: totalOperationAttempts, Err: lastErr,
	})
	c.reportOperationFailure(operation, lastErr, totalOperationAttempts, reconnectAttempted)
	return fmt.Errorf("%s: %w", operation, lastErr)
}

// isHardHealthFailure reports whether an error is strong, share-specific
// evidence that the transport or session is unhealthy: the operation consumed
// its whole hard bound rather than returning an ordinary SMB status.
func isHardHealthFailure(err error) bool {
	return errors.Is(err, ErrOperationTimeout) || errors.Is(err, ErrReconnectTimeout)
}

// reportAbandonment emits exactly one failure record when a share or target is
// abandoned, so coverage is marked incomplete without writing one entry per
// doomed object.
func (c *Client) reportAbandonment(share string, target bool, err error) {
	c.mu.Lock()
	handler := c.onFailure
	serverName := c.serverName
	c.mu.Unlock()
	if handler == nil {
		return
	}
	kind := "share abandoned"
	if target {
		kind = "target abandoned"
	}
	handler(OperationFailure{
		Operation:          kind,
		Share:              share,
		Server:             serverName,
		Category:           CategoryTransport,
		Attempts:           1,
		ReconnectAttempted: true,
		Err:                err,
	})
}

func (c *Client) run(ctx context.Context, operation, share string, progress bool, fn func(session transportSession, deadline time.Time) error) error {
	return c.runOperation(ctx, operation, share, progress, fn)
}

// reportOperationFailure emits one structured failure record for an operation
// that could not be completed.
func (c *Client) reportOperationFailure(operation string, err error, attempts int, reconnectAttempted bool) {
	if err == nil {
		return
	}
	c.mu.Lock()
	handler := c.onFailure
	serverName := c.serverName
	c.mu.Unlock()
	if handler == nil {
		return
	}
	handler(OperationFailure{
		Operation:          operation,
		Category:           CategorizeError(err),
		Attempts:           attempts,
		ReconnectAttempted: reconnectAttempted,
		Err:                err,
		Server:             serverName,
	})
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// mountTreeWithSession mounts a share over the given session within the bounded
// operation timeout, so a tree connect that never answers cannot block a worker.
func (c *Client) mountTreeWithSession(ctx context.Context, session transportSession, share string) (transportTree, error) {
	return c.mountTreeWithSessionLimit(ctx, session, share, c.operationLimit())
}

// mountTreeWithSessionLimit mounts a share within an explicit bound, so a
// caller that already holds an absolute deadline cannot overshoot it.
func (c *Client) mountTreeWithSessionLimit(ctx context.Context, session transportSession, share string, limit time.Duration) (transportTree, error) {
	if session == nil {
		return nil, ErrNotConnected
	}
	if strings.TrimSpace(share) == "" {
		return nil, fmt.Errorf("share cannot be empty")
	}
	c.mu.Lock()
	serverName := c.serverName
	c.mu.Unlock()

	mountPath := fmt.Sprintf(`\\%s\%s`, serverName, share)
	var tree transportTree
	err := c.bounded(ctx, "tree connect", limit, func() error {
		mounted, mountErr := session.Mount(mountPath)
		if mountErr != nil {
			return mountErr
		}
		tree = mounted
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}
	return tree, nil
}

// mountShare mounts a share, recovering the transport when the tree connect
// fails because the session died.
func (c *Client) mountShare(share string) (transportTree, error) {
	var tree transportTree
	err := c.run(context.Background(), "mount "+share, share, false, func(session transportSession, deadline time.Time) error {
		mounted, err := c.mountTreeWithSessionLimit(context.Background(), session, share, c.limitUntil(deadline))
		if err != nil {
			return err
		}
		tree = mounted
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tree, nil
}

// server reports the current server name for logging.
func (c *Client) server() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverName
}

func splitHost(host string) (serverName, dialAddr string, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", fmt.Errorf("host cannot be empty")
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(host); splitErr == nil {
		if parsedHost == "" {
			return "", "", fmt.Errorf("invalid host %q", host)
		}
		return parsedHost, net.JoinHostPort(parsedHost, parsedPort), nil
	}

	return host, net.JoinHostPort(host, defaultPort), nil
}

func splitUser(user string) (domain string, username string) {
	user = strings.TrimSpace(user)
	switch {
	case strings.Contains(user, `\`):
		parts := strings.SplitN(user, `\`, 2)
		return parts[0], parts[1]
	case strings.Contains(user, "@"):
		parts := strings.SplitN(user, "@", 2)
		return parts[1], parts[0]
	default:
		return "", user
	}
}

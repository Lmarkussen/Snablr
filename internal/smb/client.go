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
	maxDepth    int
	maxReadSize int64

	dialer transportDialer

	session            transportSession
	recovering         bool
	recoverDone        chan struct{}
	lastFailedRecovery time.Time

	onEvent   func(TransportEvent)
	onFailure func(OperationFailure)
	stats     TransportStats
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
		dialTimeout: defaultDialTimeout,
		maxDepth:    defaultMaxDepth,
		maxReadSize: defaultMaxReadSize,
		dialer:      smb2Dialer{},
	}
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
	dialer := c.dialer
	timeout := c.dialTimeout
	c.session = nil
	c.host = host
	c.serverName = serverName
	c.dialAddr = dialAddr
	c.auth = resolved
	c.lastFailedRecovery = time.Time{}
	c.mu.Unlock()

	if previous != nil {
		_ = previous.Close()
	}

	session, err := dialer.Dial(context.Background(), dialAddr, resolved, timeout)
	if err != nil {
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
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
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
	if c.session != nil && used != nil && c.session != used {
		// Another worker already replaced the dead session.
		c.mu.Unlock()
		return nil
	}
	if c.recovering {
		done := c.recoverDone
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
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
	dialer := c.dialer
	dialAddr := c.dialAddr
	timeout := c.dialTimeout
	serverName := c.serverName
	c.stats.ReconnectsAttempted++
	c.mu.Unlock()

	if stale != nil {
		_ = stale.Close()
	}

	session, err := dialer.Dial(ctx, dialAddr, auth, timeout)

	c.mu.Lock()
	c.recovering = false
	close(done)
	if err != nil {
		c.stats.ReconnectsFailed++
		c.session = nil
		c.lastFailedRecovery = time.Now()
		handler := c.onEvent
		c.mu.Unlock()
		emitTransportEvent(handler, TransportEvent{Kind: TransportEventRecoveryFailed, Server: serverName, Operation: "reconnect", Err: err})
		return err
	}
	c.session = session
	c.stats.ReconnectsSucceeded++
	handler := c.onEvent
	c.mu.Unlock()
	emitTransportEvent(handler, TransportEvent{Kind: TransportEventRestored, Server: serverName, Operation: "reconnect"})
	return nil
}

func emitTransportEvent(handler func(TransportEvent), event TransportEvent) {
	if handler != nil {
		handler(event)
	}
}

// runOperation executes one SMB operation with bounded transport recovery. The
// operation is retried from the beginning after a reconnect, so a file that hit
// the reset is re-read rather than skipped.
func (c *Client) runOperation(ctx context.Context, operation string, fileOperation bool, fn func(session transportSession) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	reconnectAttempted := false
	for attempt := 0; attempt < totalOperationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		session, err := c.currentSession(ctx)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.stats.OperationAttempts++
		c.mu.Unlock()

		err = fn(session)
		if err == nil {
			c.mu.Lock()
			c.stats.OperationSuccesses++
			if attempt > 0 {
				c.stats.FilesRecovered += 1
			}
			c.mu.Unlock()
			return nil
		}
		c.mu.Lock()
		c.stats.OperationFailures++
		c.mu.Unlock()
		if !isRetryableOperation(err) || ctx.Err() != nil {
			// Non-retryable failures (access denied, not found, ...) are final
			// immediately and are reported once.
			c.reportOperationFailure(operation, err, attempt+1, reconnectAttempted)
			return err
		}
		lastErr = err
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

func (c *Client) run(ctx context.Context, operation string, fn func(session transportSession) error) error {
	return c.runOperation(ctx, operation, false, fn)
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

// mountTreeWithSession mounts a share over the given session.
func (c *Client) mountTreeWithSession(session transportSession, share string) (transportTree, error) {
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
	tree, err := session.Mount(mountPath)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}
	return tree, nil
}

// mountShare mounts a share, recovering the transport when the tree connect
// fails because the session died.
func (c *Client) mountShare(share string) (transportTree, error) {
	var tree transportTree
	err := c.run(context.Background(), "mount "+share, func(session transportSession) error {
		mounted, err := c.mountTreeWithSession(session, share)
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

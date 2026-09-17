package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// Transport ownership
//
// A Client owns exactly one TCP transport and one authenticated session per
// host. Trees are mounted per operation and unmounted by the caller, so no tree
// connection is cached across operations. When the transport dies every cached
// handle (session, tree, file) becomes stale, so recovery works in one place:
// invalidate the session, reconnect with the same operator credential context,
// and let the caller retry the operation it was performing.

const (
	// maxReconnectAttempts bounds reconnects per operation.
	maxReconnectAttempts = 2
	// totalOperationAttempts is the original attempt plus the reconnect budget.
	totalOperationAttempts = 1 + maxReconnectAttempts
	// reconnectCooldown prevents a reconnect storm while the server is down.
	reconnectCooldown = 2 * time.Second
	// reconnectBackoff is the pause before retrying an operation.
	reconnectBackoff = 100 * time.Millisecond

	// Bounded operation timing.
	//
	// Every network-facing call is wrapped in a hard watchdog. Only the TCP
	// connect has an OS-level timeout; negotiation, session setup, tree connect,
	// directory enumeration, open and read all use blocking socket I/O that a
	// wedged server (or a filtering device that accepts and then stays silent)
	// would otherwise hold forever. With these bounds the worst case for one
	// operation is finite and the scan always makes forward progress.
	//
	// defaultHandshakeTimeout bounds SMB negotiate plus session setup.
	defaultHandshakeTimeout = 20 * time.Second
	// defaultOperationTimeout bounds one SMB request phase: tree connect,
	// directory enumeration, stat, open, umount or share listing.
	defaultOperationTimeout = 30 * time.Second
	// defaultReadIdleTimeout bounds the time between read progress. A read that
	// keeps delivering data is allowed to continue; a stalled read is abandoned.
	defaultReadIdleTimeout = 60 * time.Second
	// defaultReadTotalTimeout is the absolute wall-clock bound on reading one
	// object, independent of progress. The idle timeout alone is not sufficient:
	// a peer that delivers a little data just before each idle deadline
	// refreshes it forever, so the read must also have a hard end.
	//
	// Rationale for five minutes: the default maximum object is 10 MiB and the
	// read granularity is 512 KiB, so five minutes still admits a sustained
	// throughput of roughly 35 KiB/s for a maximum-size object. That is
	// generous for a LAN or WAN share while keeping any single object's read
	// finite. Operators reading much larger objects can raise it.
	defaultReadTotalTimeout = 5 * time.Minute
	// defaultReconnectWaitLimit is the hard cap on waiting for a coordinated
	// reconnect, so waiters are released even if the leader cannot be interrupted.
	defaultReconnectWaitLimit = 45 * time.Second
	// defaultSessionCloseTimeout bounds the logoff that precedes a socket close.
	// Logoff is a network request: without a bound a server that accepts requests
	// and never answers could block recovery or target cleanup forever, because
	// the operation deadline is cleared after the handshake and every close path
	// (reconnect leader, client close) runs outside the per-phase watchdog.
	defaultSessionCloseTimeout = 2 * time.Second
	// defaultRecoveryBudget is the hard cap on one operation including every
	// reconnect, backoff and retry. When it is exhausted the operation becomes a
	// final failure and the scan continues.
	defaultRecoveryBudget = 2 * time.Minute
)

// ErrOperationTimeout reports that one SMB request phase exceeded its bound and
// the transport was invalidated.
var ErrOperationTimeout = errors.New("smb operation timed out")

// ErrReconnectTimeout reports that a coordinated reconnect did not complete
// inside its bound. Waiting workers are released with this error.
var ErrReconnectTimeout = errors.New("smb reconnect timed out")

// ErrAuthFailure reports a terminal authentication failure. It is never retried
// and never triggers transport recovery.
var ErrAuthFailure = errors.New("smb authentication failed")

// operationTimeoutError carries the operation and the bound that expired.
type operationTimeoutError struct {
	Operation string
	Limit     time.Duration
}

func (e *operationTimeoutError) Error() string {
	return fmt.Sprintf("smb operation timed out after %s: %s", e.Limit, e.Operation)
}

func (e *operationTimeoutError) Unwrap() error { return ErrOperationTimeout }

// NTSTATUS codes for authentication and account-policy failures. These are
// terminal: retrying or reconnecting cannot help and must not happen.
const (
	ntStatusLogonFailure        = 0xC000006D
	ntStatusAccountRestriction  = 0xC000006E
	ntStatusInvalidLogonHours   = 0xC0000070
	ntStatusPasswordExpired     = 0xC0000071
	ntStatusAccountDisabled     = 0xC0000072
	ntStatusPasswordMustChange  = 0xC0000224
	ntStatusLogonTypeNotGranted = 0xC000015B
)

// IsAuthFailure reports whether err is a terminal authentication failure. Such
// failures must fail fast: no reconnect, no retry, no reconnect storm.
func IsAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAuthFailure) {
		return true
	}
	var responseErr *smb2.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.Code {
		case ntStatusLogonFailure,
			ntStatusAccountRestriction,
			ntStatusInvalidLogonHours,
			ntStatusPasswordExpired,
			ntStatusAccountDisabled,
			ntStatusPasswordMustChange,
			ntStatusLogonTypeNotGranted:
			return true
		}
	}
	message := strings.ToLower(err.Error())
	for _, token := range []string{
		"logon failure",
		"invalid credentials",
		"authentication failed",
		"bad password",
		"password expired",
		"account disabled",
		"logon type not granted",
		"krb_ap_err",
		"preauth",
		"kinit",
	} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

// NTSTATUS codes that mean the session or connection is gone. Everything else
// the server reports (access denied, not found, bad password, sharing
// violation, ...) is a normal SMB status and must never trigger a reconnect.
const (
	ntStatusNetworkNameDeleted     = 0xC00000C9
	ntStatusUnexpectedNetworkError = 0xC00000C4
	ntStatusRemoteDisconnect       = 0xC000013C
	ntStatusUserSessionDeleted     = 0xC0000203
	ntStatusConnectionDisconnected = 0xC000020C
	ntStatusConnectionReset        = 0xC000020D
	ntStatusNetworkSessionExpired  = 0xC000035C
	// Stale-handle statuses: the operation must be re-run (re-open), but the
	// transport is healthy, so no reconnect is required.
	ntStatusInvalidHandle       = 0xC0000008
	ntStatusFileClosed          = 0xC0000128
	ntStatusAccessDenied        = 0xC0000022
	ntStatusNetworkAccessDenied = 0xC00000CA
	ntStatusObjectNameNotFound  = 0xC0000034
	ntStatusObjectPathNotFound  = 0xC000003A
	ntStatusNoSuchFile          = 0xC000000F
	ntStatusIOTimeout           = 0xC00000B5
)

// IsReconnectable reports whether err means the SMB transport or session died
// and the client must reconnect before any further operation can succeed.
func IsReconnectable(err error) bool {
	if err == nil {
		return false
	}
	// Authentication failures are terminal: reconnecting cannot help.
	if IsAuthFailure(err) {
		return false
	}
	// A watchdog timeout means the operation was abandoned mid-flight, so the
	// SMB framing state is unknown and the transport must be re-established.
	if errors.Is(err, ErrOperationTimeout) {
		return true
	}
	// Cancellation and per-operation deadlines are caller decisions, not
	// evidence of a dead transport.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	for _, target := range []error{
		net.ErrClosed,
		io.EOF,
		io.ErrUnexpectedEOF,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EPIPE,
		syscall.ENOTCONN,
		syscall.ETIMEDOUT,
		syscall.EHOSTDOWN,
		syscall.EHOSTUNREACH,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	// The SMB dependency exposes the transport layer as a typed error.
	var transportErr *smb2.TransportError
	if errors.As(err, &transportErr) {
		return true
	}
	var responseErr *smb2.ResponseError
	if errors.As(err, &responseErr) {
		return reconnectableStatus(responseErr.Code)
	}
	// Fallback for platform/dependency errors that carry no typed value.
	message := strings.ToLower(err.Error())
	for _, token := range []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"unexpected eof",
		"connection aborted",
		"network name deleted",
		"network name is no longer available",
		"connection disconnected",
		"network session expired",
		"transport endpoint is not connected",
		"the specified network name",
	} {
		if strings.Contains(message, token) {
			return true
		}
	}
	return false
}

// isRetryableOperation reports whether re-running the whole operation (re-open,
// re-stat, re-mount as needed) can succeed. It is a superset of
// IsReconnectable: a stale handle only needs the operation re-run.
func isRetryableOperation(err error) bool {
	if err == nil {
		return false
	}
	// Terminal authentication failures and caller cancellation are never retried.
	if IsAuthFailure(err) {
		return false
	}
	if IsReconnectable(err) {
		return true
	}
	var responseErr *smb2.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.Code {
		case ntStatusInvalidHandle, ntStatusFileClosed:
			return true
		}
	}
	return errors.Is(err, syscall.EBADF)
}

func reconnectableStatus(code uint32) bool {
	switch code {
	case ntStatusNetworkNameDeleted,
		ntStatusUnexpectedNetworkError,
		ntStatusRemoteDisconnect,
		ntStatusUserSessionDeleted,
		ntStatusConnectionDisconnected,
		ntStatusConnectionReset,
		ntStatusNetworkSessionExpired:
		return true
	default:
		return false
	}
}

// TransportStats is a run-local snapshot of transport recovery accounting.
// It contains no credential material.
type TransportStats struct {
	OperationAttempts   int64 `json:"operation_attempts"`
	OperationSuccesses  int64 `json:"operation_successes"`
	OperationFailures   int64 `json:"operation_failures"`
	OperationsRetried   int64 `json:"operations_retried"`
	TransportFailures   int64 `json:"transport_failures"`
	ReconnectsAttempted int64 `json:"reconnects_attempted"`
	ReconnectsSucceeded int64 `json:"reconnects_succeeded"`
	ReconnectsFailed    int64 `json:"reconnects_failed"`
	FilesRecovered      int64 `json:"files_recovered"`
	RetryExhausted      int64 `json:"retry_exhausted"`
	EnumerationFailures int64 `json:"enumeration_failures"`
	// OperationTimeouts counts request phases abandoned by the watchdog.
	OperationTimeouts int64 `json:"operation_timeouts"`
	// AuthFailures counts terminal authentication failures. These never retry.
	AuthFailures int64 `json:"auth_failures"`
	// SharesWithheld counts shares temporarily held back from work after
	// repeated transport failures, and SharesAbandoned counts those whose
	// recovery budget was spent.
	SharesWithheld  int64 `json:"shares_withheld"`
	SharesAbandoned int64 `json:"shares_abandoned"`
	// OperationsFastFailed counts operations that failed without touching the
	// network because their share or target was already abandoned.
	OperationsFastFailed int64 `json:"operations_fast_failed"`
	// OperationsResumed counts operations that succeeded after being held back
	// by transport containment, i.e. content inspection that was delayed by a
	// transient fault rather than lost.
	OperationsResumed int64 `json:"operations_resumed"`
}

// TransportEventKind classifies a transport lifecycle event.
type TransportEventKind int

const (
	// TransportEventRetrying is emitted before a coordinated reconnect.
	TransportEventRetrying TransportEventKind = iota
	// TransportEventRestored is emitted after a successful reconnect.
	TransportEventRestored
	// TransportEventRecoveryFailed is emitted when a reconnect failed.
	TransportEventRecoveryFailed
	// TransportEventRetryExhausted is emitted when the retry budget ran out.
	TransportEventRetryExhausted
)

// TransportEvent is a structured transport lifecycle event for logging. It
// never carries credentials.
type TransportEvent struct {
	Kind        TransportEventKind
	Server      string
	Share       string
	Operation   string
	Attempt     int
	MaxAttempts int
	Err         error
}

// ErrorCategory is the stable classification of an SMB failure. It is used for
// operator-facing failure reporting so categories do not depend on error text.
type ErrorCategory string

const (
	CategoryTransport    ErrorCategory = "SMB transport"
	CategoryMount        ErrorCategory = "tree connect"
	CategoryEnumeration  ErrorCategory = "directory enumeration"
	CategoryAccessDenied ErrorCategory = "access denied"
	CategoryNotFound     ErrorCategory = "not found"
	CategoryTimeout      ErrorCategory = "timeout"
	CategoryAuthFailure  ErrorCategory = "authentication"
	CategorySizeLimit    ErrorCategory = "resource/size limit"
	CategoryRead         ErrorCategory = "read failure"
	CategoryOther        ErrorCategory = "other"
)

// CategorizeError classifies an SMB error without relying on raw text where the
// transport exposes structured information.
func CategorizeError(err error) ErrorCategory {
	if err == nil {
		return CategoryOther
	}
	if IsAuthFailure(err) {
		return CategoryAuthFailure
	}
	if errors.Is(err, ErrOperationTimeout) {
		return CategoryTimeout
	}
	if errors.Is(err, ErrFileTooLarge) {
		return CategorySizeLimit
	}
	if errors.Is(err, os.ErrPermission) {
		return CategoryAccessDenied
	}
	if errors.Is(err, os.ErrNotExist) {
		return CategoryNotFound
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return CategoryTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTimeout
	}
	var responseErr *smb2.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.Code {
		case ntStatusAccessDenied, ntStatusNetworkAccessDenied:
			return CategoryAccessDenied
		case ntStatusObjectNameNotFound, ntStatusObjectPathNotFound, ntStatusNoSuchFile:
			return CategoryNotFound
		case ntStatusIOTimeout:
			return CategoryTimeout
		case ntStatusNetworkNameDeleted:
			return CategoryMount
		case ntStatusUserSessionDeleted, ntStatusNetworkSessionExpired:
			return CategoryTransport
		}
	}
	if IsReconnectable(err) {
		return CategoryTransport
	}
	return CategoryRead
}

// OperationFailure describes one operation that ultimately failed. It is
// reported once per operation, never once per reconnect attempt.
type OperationFailure struct {
	Operation          string
	Share              string
	Path               string
	Server             string
	Category           ErrorCategory
	Attempts           int
	ReconnectAttempted bool
	Err                error
}

// AttemptsUsed reports how many attempts the retry budget allowed.
func (f OperationFailure) AttemptsUsed() int {
	if f.Attempts > 0 {
		return f.Attempts
	}
	return 1
}

// transportSession is the authenticated session owned by a Client.
type transportSession interface {
	Mount(path string) (transportTree, error)
	ListSharenames() ([]string, error)
	// Close attempts a clean logoff and always closes the underlying transport
	// so a dead session cannot leak a socket or be reused.
	Close() error
}

// transportTree is one mounted share (tree connection).
type transportTree interface {
	ReadDir(path string) ([]fs.FileInfo, error)
	Stat(path string) (fs.FileInfo, error)
	Open(path string) (transportFile, error)
	Umount() error
	MkdirAll(path string, perm fs.FileMode) error
	WriteFile(name string, data []byte, perm fs.FileMode) error
	RemoveAll(path string) error
}

// transportFile is a remote file handle.
type transportFile interface {
	io.Reader
	io.Closer
}

// transportDialer establishes a new authenticated session. It is an interface so
// fault injection can drive recovery deterministically.
type transportDialer interface {
	Dial(ctx context.Context, dialAddr string, auth resolvedAuth, dialTimeout, handshakeTimeout time.Duration) (transportSession, error)
}

// smb2Dialer is the production dialer: one TCP transport plus SMB2 negotiation
// and authentication using the operator's existing credential context.
type smb2Dialer struct{}

func (smb2Dialer) Dial(ctx context.Context, dialAddr string, auth resolvedAuth, dialTimeout, handshakeTimeout time.Duration) (transportSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	// The TCP connect is cancellable and bounded; the SMB handshake that follows
	// is bounded by a socket deadline so a server that accepts the connection and
	// then stops answering cannot block negotiate or session setup.
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}
	initiator, err := auth.initiator()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Closing the socket on cancellation interrupts an in-flight handshake; the
	// watcher always exits with the handshake.
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-handshakeDone:
		}
	}()
	session, err := (&smb2.Dialer{Initiator: initiator}).DialContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = session.Logoff()
		_ = conn.Close()
		return nil, err
	}
	return &smb2Session{session: session, conn: conn}, nil
}

type smb2Session struct {
	session *smb2.Session
	conn    net.Conn
	mu      sync.Mutex
}

func (s *smb2Session) Mount(path string) (transportTree, error) {
	share, err := s.session.Mount(path)
	if err != nil {
		return nil, err
	}
	return &smb2Tree{share: share}, nil
}

func (s *smb2Session) ListSharenames() ([]string, error) {
	return s.session.ListSharenames()
}

func (s *smb2Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.session != nil {
		// Bound the logoff so a server that stops answering after the session was
		// established cannot hold a reconnect leader or target cleanup open. The
		// socket is still closed unconditionally below, which is what actually
		// releases any blocked call.
		if s.conn != nil {
			_ = s.conn.SetDeadline(time.Now().Add(defaultSessionCloseTimeout))
		}
		if err := s.session.Logoff(); err != nil && !isIgnorableCloseError(err) {
			errs = append(errs, err)
		}
		s.session = nil
	}
	if s.conn != nil {
		if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !isIgnorableCloseError(err) {
			errs = append(errs, err)
		}
		s.conn = nil
	}
	return errors.Join(errs...)
}

type smb2Tree struct {
	share *smb2.Share
}

func (t *smb2Tree) ReadDir(path string) ([]fs.FileInfo, error) {
	return t.share.ReadDir(path)
}

func (t *smb2Tree) Stat(path string) (fs.FileInfo, error) {
	return t.share.Stat(path)
}

func (t *smb2Tree) Open(path string) (transportFile, error) {
	return t.share.Open(path)
}

func (t *smb2Tree) Umount() error {
	return t.share.Umount()
}

func (t *smb2Tree) MkdirAll(path string, perm fs.FileMode) error {
	return t.share.MkdirAll(path, perm)
}

func (t *smb2Tree) WriteFile(name string, data []byte, perm fs.FileMode) error {
	return t.share.WriteFile(name, data, perm)
}

func (t *smb2Tree) RemoveAll(path string) error {
	return t.share.RemoveAll(path)
}

package smb

import (
	"context"
	"errors"
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
)

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
	Dial(ctx context.Context, dialAddr string, auth resolvedAuth, timeout time.Duration) (transportSession, error)
}

// smb2Dialer is the production dialer: one TCP transport plus SMB2 negotiation
// and authentication using the operator's existing credential context.
type smb2Dialer struct{}

func (smb2Dialer) Dial(ctx context.Context, dialAddr string, auth resolvedAuth, timeout time.Duration) (transportSession, error) {
	conn, err := net.DialTimeout("tcp", dialAddr, timeout)
	if err != nil {
		return nil, err
	}
	initiator, err := auth.initiator()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	session, err := (&smb2.Dialer{Initiator: initiator}).DialContext(ctx, conn)
	if err != nil {
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

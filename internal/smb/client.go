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
	user       string
	password   string
	domain     string

	dialTimeout time.Duration
	maxDepth    int
	maxReadSize int64

	conn    net.Conn
	session *smb2.Session

	// baseCtx cancels in-flight operations when the scan is interrupted;
	// opTimeout bounds each operation (idle limit for reads and listings).
	baseCtx             context.Context
	opTimeout           time.Duration
	consecutiveTimeouts int
	unresponsive        bool
}

func NewClient() *Client {
	return &Client{
		dialTimeout: defaultDialTimeout,
		maxDepth:    defaultMaxDepth,
		maxReadSize: defaultMaxReadSize,
		baseCtx:     context.Background(),
		opTimeout:   DefaultOperationTimeout,
	}
}

func (c *Client) SetMaxReadSize(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxReadSize = limit
}

// readLimit returns the read size limit; SetMaxReadSize writes it under c.mu.
func (c *Client) readLimit() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxReadSize
}

func (c *Client) Connect(host, user, pass string) error {
	return c.ConnectWithAuth(host, NewPasswordAuth(user, "", pass))
}

func (c *Client) ConnectWithAuth(host string, auth Auth) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil || c.conn != nil {
		_ = c.closeLocked()
	}

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

	base := c.baseCtx
	if base == nil {
		base = context.Background()
	}
	c.unresponsive, c.consecutiveTimeouts = false, 0
	conn, err := (&net.Dialer{Timeout: c.dialTimeout}).DialContext(base, "tcp", dialAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", dialAddr, err)
	}

	var initiator smb2.Initiator
	if auth.Mode == AuthModeKerberos {
		ccache, err := smbkerberos.ResolveCCache(auth.CCache)
		if err != nil {
			_ = conn.Close()
			return err
		}
		mechanism, err := smbkerberos.NewFromCCache(ccache, smbkerberos.ResolveConfig(), auth.SPN)
		if err != nil {
			_ = conn.Close()
			return err
		}
		initiator = mechanism
	} else {
		initiator = newNTLMInitiator(auth, username, domain)
	}
	dialer := &smb2.Dialer{Initiator: initiator}

	// Negotiation and session setup are bounded so a host that accepts TCP but
	// never answers SMB cannot stall the scan.
	setup := newIdleWatchdog(base, c.opTimeout)
	session, err := dialer.DialContext(setup.ctx, conn)
	setup.stop()
	if err != nil {
		_ = conn.Close()
		var contextErr *smb2.ContextError
		switch {
		case base.Err() != nil:
			return fmt.Errorf("authenticate to %s: %w", serverName, base.Err())
		case errors.As(err, &contextErr):
			return fmt.Errorf("authenticate to %s: %w after %s without progress", serverName, ErrOperationTimeout, c.opTimeout)
		}
		return fmt.Errorf("authenticate to %s: %w", serverName, err)
	}

	c.host = host
	c.serverName = serverName
	c.user = username
	c.password = auth.Password
	c.domain = domain
	c.conn = conn
	c.session = session

	return nil
}

func newNTLMInitiator(auth Auth, username, domain string) *smb2.NTLMInitiator {
	initiator := &smb2.NTLMInitiator{User: username, Domain: domain}
	if auth.Mode == AuthModeNTHash {
		initiator.Hash = append([]byte(nil), auth.NTHash[:]...)
		return initiator
	}
	initiator.Password = auth.Password
	return initiator
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	var errs []error

	if c.session != nil {
		ctx, cancel := cleanupContext()
		err := c.session.WithContext(ctx).Logoff()
		cancel()
		if err != nil && !isIgnorableCloseError(err) {
			errs = append(errs, err)
		}
		c.session = nil
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && !isIgnorableCloseError(err) {
			errs = append(errs, err)
		}
		c.conn = nil
	}

	c.host = ""
	c.serverName = ""
	c.user = ""
	c.password = ""
	c.domain = ""

	if len(errs) > 0 {
		return errors.Join(errs...)
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
	// A bounded logoff against an unresponsive host is best effort.
	var contextErr *smb2.ContextError
	if errors.As(err, &contextErr) {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "connection already closed")
}

func (c *Client) connectedSession() (*smb2.Session, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return nil, "", ErrNotConnected
	}
	return c.session, c.serverName, nil
}

func (c *Client) mountShare(share string) (*smb2.Share, error) {
	session, serverName, err := c.connectedSession()
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(share) == "" {
		return nil, fmt.Errorf("share cannot be empty")
	}

	mountPath := fmt.Sprintf(`\\%s\%s`, serverName, share)
	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}
	defer watchdog.stop()
	fs, err := session.WithContext(watchdog.ctx).Mount(mountPath)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, c.observe(err))
	}
	_ = c.observe(nil)
	return fs, nil
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

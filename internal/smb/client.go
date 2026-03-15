package smb

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

const (
	defaultPort        = "445"
	defaultDialTimeout = 5 * time.Second
	defaultMaxDepth    = 64
	defaultMaxReadSize = 4 * 1024 * 1024
)

var (
	ErrNotConnected = errors.New("smb client is not connected")
	ErrFileTooLarge = errors.New("remote file exceeds configured read limit")
)

type RemoteFile struct {
	Host      string
	Share     string
	Path      string
	Name      string
	Size      int64
	IsDir     bool
	Extension string
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
}

func NewClient() *Client {
	return &Client{
		dialTimeout: defaultDialTimeout,
		maxDepth:    defaultMaxDepth,
		maxReadSize: defaultMaxReadSize,
	}
}

func (c *Client) Connect(host, user, pass string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil || c.conn != nil {
		_ = c.closeLocked()
	}

	serverName, dialAddr, err := splitHost(host)
	if err != nil {
		return err
	}

	domain, username := splitUser(user)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	conn, err := net.DialTimeout("tcp", dialAddr, c.dialTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", dialAddr, err)
	}

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: pass,
			Domain:   domain,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("authenticate to %s: %w", serverName, err)
	}

	c.host = host
	c.serverName = serverName
	c.user = username
	c.password = pass
	c.domain = domain
	c.conn = conn
	c.session = session

	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	var errs []error

	if c.session != nil {
		if err := c.session.Logoff(); err != nil {
			errs = append(errs, err)
		}
		c.session = nil
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
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
	fs, err := session.Mount(mountPath)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}
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

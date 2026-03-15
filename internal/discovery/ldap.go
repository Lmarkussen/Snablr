package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	defaultLDAPPort    = 389
	defaultLDAPTimeout = 5 * time.Second
	defaultPageSize    = 500
)

type rootDSEInfo struct {
	DefaultNamingContext string
	RootNamingContext    string
}

func DiscoverLDAP(ctx context.Context, opts LDAPOptions, logger Logger) ([]DiscoveredHost, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultLDAPTimeout
	}
	if opts.PageSize == 0 {
		opts.PageSize = defaultPageSize
	}

	domainContext, err := DetectDomainContext(ctx, opts, logger)
	if err != nil {
		return nil, err
	}
	if domainContext.DomainController == "" {
		return nil, fmt.Errorf("unable to determine a domain controller for ldap discovery")
	}

	conn, err := dialLDAP(domainContext.DomainController, opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := bindLDAP(conn, opts, domainContext.DomainName); err != nil {
		return nil, err
	}

	rootDSE, err := queryRootDSE(conn)
	if err != nil {
		return nil, err
	}

	if domainContext.BaseDN == "" {
		domainContext.BaseDN = rootDSE.DefaultNamingContext
	}
	if domainContext.BaseDN == "" {
		domainContext.BaseDN = rootDSE.RootNamingContext
	}
	if domainContext.BaseDN == "" {
		return nil, fmt.Errorf("ldap discovery: rootDSE did not return a naming context")
	}
	if logger != nil {
		logger.Infof("ldap discovery: searching base DN %s", domainContext.BaseDN)
	}

	return queryComputerObjects(conn, domainContext.BaseDN, opts.PageSize, logger)
}

func dialLDAP(dc string, timeout time.Duration) (*ldap.Conn, error) {
	address := dc
	if _, _, err := net.SplitHostPort(dc); err != nil {
		address = net.JoinHostPort(dc, fmt.Sprintf("%d", defaultLDAPPort))
	}

	conn, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, fmt.Errorf("ldap discovery: connect to %s failed: %w", address, err)
	}
	conn.SetTimeout(timeout)
	return conn, nil
}

func bindLDAP(conn *ldap.Conn, opts LDAPOptions, domain string) error {
	username := strings.TrimSpace(opts.Username)
	password := opts.Password
	if username == "" {
		return nil
	}

	bindUser := normalizeBindUser(username, domain)
	if err := conn.Bind(bindUser, password); err != nil {
		return fmt.Errorf("ldap discovery: bind failed for %s: %w", bindUser, err)
	}
	return nil
}

func normalizeBindUser(username, domain string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return ""
	}
	if strings.Contains(username, "@") || strings.Contains(username, `\`) {
		return username
	}
	if strings.TrimSpace(domain) == "" {
		return username
	}
	return username + "@" + domain
}

func queryRootDSE(conn *ldap.Conn) (rootDSEInfo, error) {
	request := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext"},
		nil,
	)

	result, err := conn.Search(request)
	if err != nil {
		return rootDSEInfo{}, fmt.Errorf("ldap discovery: rootDSE query failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return rootDSEInfo{}, fmt.Errorf("ldap discovery: rootDSE query returned no entries")
	}

	entry := result.Entries[0]
	return rootDSEInfo{
		DefaultNamingContext: entry.GetAttributeValue("defaultNamingContext"),
		RootNamingContext:    entry.GetAttributeValue("rootDomainNamingContext"),
	}, nil
}

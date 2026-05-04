package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ldapSession struct {
	Conn       *ldap.Conn
	RootDSE    rootDSEInfo
	AuthMethod string
}

func ValidateLDAPCredentials(ctx context.Context, opts LDAPOptions, logger Logger) error {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultLDAPTimeout
	}

	domainContext, err := DetectDomainContext(ctx, opts, logger)
	if err != nil {
		return err
	}
	if domainContext.DomainController == "" {
		return fmt.Errorf("ldap discovery: unable to determine a domain controller for credential validation")
	}

	session, err := connectLDAPSession(opts, &domainContext, logger)
	if err != nil {
		return err
	}
	defer session.Conn.Close()

	return nil
}

func connectLDAPSession(opts LDAPOptions, domainContext *DomainContext, logger Logger) (ldapSession, error) {
	if domainContext == nil || strings.TrimSpace(domainContext.DomainController) == "" {
		return ldapSession{}, fmt.Errorf("ldap discovery: missing domain controller for ldap session")
	}

	conn, err := dialLDAP(domainContext.DomainController, opts.Timeout)
	if err != nil {
		return ldapSession{}, err
	}

	rootDSE, err := preBindRootDSE(conn, domainContext, logger)
	if err != nil {
		conn.Close()
		return ldapSession{}, err
	}

	authedConn, method, err := authenticateLDAP(conn, opts, domainContext.DomainName, domainContext.DomainController, logger)
	if err != nil {
		conn.Close()
		return ldapSession{}, err
	}

	return ldapSession{
		Conn:       authedConn,
		RootDSE:    rootDSE,
		AuthMethod: method,
	}, nil
}

func authenticateLDAP(conn *ldap.Conn, opts LDAPOptions, domain, domainController string, logger Logger) (*ldap.Conn, string, error) {
	if method, err := bindLDAPSimple(conn, opts, domain, logger); err == nil {
		return conn, method, nil
	} else if !requiresLDAPSigning(err) {
		return nil, "", err
	}

	if logger != nil {
		logger.Infof("ldap discovery: simple bind on LDAP requires stronger authentication, retrying with LDAPS")
	}

	conn.Close()

	ldapsConn, err := dialLDAPS(domainController, opts.Timeout)
	if err != nil {
		return nil, "", fmt.Errorf("ldap discovery: stronger authentication required and LDAPS fallback failed: %w", err)
	}

	method, err := bindLDAPSimple(ldapsConn, opts, domain, logger)
	if err != nil {
		ldapsConn.Close()
		return nil, "", fmt.Errorf("ldap discovery: stronger authentication required and LDAPS fallback bind failed: %w", err)
	}
	return ldapsConn, "ldaps-simple/" + method, nil
}

func dialLDAPS(dc string, timeout time.Duration) (*ldap.Conn, error) {
	address, host := ldapAddress(dc, defaultLDAPSPort)
	conn, err := ldap.DialURL("ldaps://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}), ldap.DialWithTLSConfig(&tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}))
	if err != nil {
		return nil, fmt.Errorf("ldap discovery: connect to %s failed: %w", address, err)
	}
	conn.SetTimeout(timeout)
	return conn, nil
}

func ldapAddress(dc string, defaultPort int) (string, string) {
	address := dc
	host := dc
	if parsedHost, _, err := net.SplitHostPort(dc); err == nil {
		host = parsedHost
		return dc, host
	}

	host = dc
	address = net.JoinHostPort(dc, fmt.Sprintf("%d", defaultPort))
	return address, host
}

func bindLDAPSimple(conn *ldap.Conn, opts LDAPOptions, domain string, logger Logger) (string, error) {
	username := strings.TrimSpace(opts.Username)
	password := opts.Password
	if username == "" {
		return "anonymous", nil
	}

	attempts := bindCandidates(username, domain)
	var lastErr error
	for _, attempt := range attempts {
		if err := conn.Bind(attempt.Value, password); err != nil {
			lastErr = err
			continue
		}
		method := "ldap-simple"
		if logger != nil {
			logger.Infof("ldap discovery: bind successful using %s format: %s via %s", attempt.Label, attempt.Value, method)
		}
		return method, nil
	}
	if len(attempts) == 1 {
		return "", fmt.Errorf("ldap discovery: bind failed for %s: %w", attempts[0].Value, lastErr)
	}
	return "", fmt.Errorf("ldap discovery: bind failed after trying %d username formats for %s: %w", len(attempts), username, lastErr)
}

func requiresLDAPSigning(err error) bool {
	if err == nil {
		return false
	}

	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultConfidentialityRequired:
			return true
		}
	}

	message := strings.ToLower(err.Error())
	signingHints := []string{
		"strongerauthrequired",
		"strong auth required",
		"confidentiality required",
		"integrity checking",
	}
	for _, hint := range signingHints {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

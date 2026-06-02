package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/credentials"
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

	if normalizeAuthMode(opts.AuthMode) == AuthModeKerberos {
		authedConn, method, err := authenticateLDAP(conn, opts, domainContext.DomainName, domainContext.DomainController, logger)
		if err != nil {
			conn.Close()
			return ldapSession{}, err
		}
		rootDSE, err := preBindRootDSE(authedConn, domainContext, logger)
		if err != nil {
			authedConn.Close()
			return ldapSession{}, err
		}
		return ldapSession{
			Conn:       authedConn,
			RootDSE:    rootDSE,
			AuthMethod: method,
		}, nil
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
	switch normalizeAuthMode(opts.AuthMode) {
	case AuthModeKerberos:
		method, err := bindLDAPKerberos(conn, opts, domainController, logger)
		if err != nil {
			return nil, "", err
		}
		return conn, method, nil
	case AuthModePassword:
	default:
		return nil, "", fmt.Errorf("ldap discovery: unsupported auth mode %q", opts.AuthMode)
	}

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

func bindLDAPKerberos(conn *ldap.Conn, opts LDAPOptions, domainController string, logger Logger) (string, error) {
	ccachePath, err := resolveKerberosCCache(opts.KerberosCCache)
	if err != nil {
		return "", err
	}
	if err := validateKerberosCCache(ccachePath); err != nil {
		return "", err
	}

	spn, err := resolveLDAPSPN(domainController, opts.LDAPSPN)
	if err != nil {
		return "", err
	}

	krb5Config := strings.TrimSpace(os.Getenv("KRB5_CONFIG"))
	if krb5Config == "" {
		krb5Config = "/etc/krb5.conf"
	}
	client, err := gssapi.NewClientFromCCache(ccachePath, krb5Config)
	if err != nil {
		return "", fmt.Errorf("ldap discovery: invalid kerberos ccache or krb5 config: %w", err)
	}
	defer client.Close()

	if err := conn.GSSAPIBind(client, spn, ""); err != nil {
		return "", fmt.Errorf("ldap discovery: kerberos GSSAPI bind failed for %s: %w", spn, err)
	}
	if logger != nil {
		logger.Infof("ldap discovery: kerberos GSSAPI bind successful using %s", spn)
	}
	return "ldap-kerberos-gssapi", nil
}

func normalizeAuthMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return AuthModePassword
	}
	return mode
}

func resolveKerberosCCache(override string) (string, error) {
	value := strings.TrimSpace(override)
	if value == "" {
		value = strings.TrimSpace(os.Getenv("KRB5CCNAME"))
	}
	if value == "" {
		return "", fmt.Errorf("ldap discovery: kerberos auth requires a credential cache; set KRB5CCNAME or pass --kerberos-ccache")
	}
	if strings.HasPrefix(value, "FILE:") {
		value = strings.TrimPrefix(value, "FILE:")
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("ldap discovery: unsupported kerberos credential cache type %q; use a FILE ccache path", value)
	}
	return value, nil
}

func validateKerberosCCache(path string) error {
	ccache, err := credentials.LoadCCache(path)
	if err != nil {
		return fmt.Errorf("ldap discovery: unable to load kerberos ccache %s: %w", path, err)
	}
	entries := ccache.GetEntries()
	if len(entries) == 0 {
		return fmt.Errorf("ldap discovery: kerberos ccache %s contains no usable tickets", path)
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		if !entry.StartTime.IsZero() && now.Before(entry.StartTime) {
			continue
		}
		if !entry.EndTime.IsZero() && now.Before(entry.EndTime) {
			return nil
		}
	}
	return fmt.Errorf("ldap discovery: kerberos ccache %s contains no valid unexpired tickets", path)
}

func resolveLDAPSPN(domainController, override string) (string, error) {
	spn := strings.TrimSpace(override)
	if spn != "" {
		return spn, nil
	}
	host := ldapHost(domainController)
	if host == "" {
		return "", fmt.Errorf("ldap discovery: kerberos auth requires a domain controller hostname or --ldap-spn")
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("ldap discovery: kerberos auth requires --ldap-spn when --dc is an IP address")
	}
	return "ldap/" + strings.ToLower(host), nil
}

func ldapHost(dc string) string {
	dc = strings.TrimSpace(dc)
	if dc == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(dc); err == nil {
		return strings.TrimSpace(host)
	}
	return dc
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

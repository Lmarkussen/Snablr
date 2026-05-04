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
	defaultLDAPSPort   = 636
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

	session, err := connectLDAPSession(opts, &domainContext, logger)
	if err != nil {
		return nil, err
	}
	defer session.Conn.Close()

	rootDSE := session.RootDSE
	if rootDSE.DefaultNamingContext == "" && rootDSE.RootNamingContext == "" {
		rootDSE, err = queryRootDSE(session.Conn)
		if err != nil {
			return nil, err
		}
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
		logger.Infof("ldap discovery: searching base DN %s using %s", domainContext.BaseDN, session.AuthMethod)
	}

	return queryComputerObjects(session.Conn, domainContext.BaseDN, opts.PageSize, logger)
}

func preBindRootDSE(conn *ldap.Conn, domainContext *DomainContext, logger Logger) (rootDSEInfo, error) {
	if domainContext == nil {
		return rootDSEInfo{}, nil
	}

	rootDSE, err := queryRootDSE(conn)
	if err != nil {
		if logger != nil {
			logger.Debugf("ldap discovery: pre-bind rootDSE query failed: %v", err)
		}
		return rootDSEInfo{}, nil
	}

	namingContext := rootDSE.DefaultNamingContext
	if namingContext == "" {
		namingContext = rootDSE.RootNamingContext
	}
	derivedDomain := domainFromNamingContext(namingContext)
	if derivedDomain == "" {
		return rootDSE, nil
	}

	currentDomain := normalizeDetectedDomain(domainContext.DomainName)
	switch {
	case currentDomain == "":
		domainContext.DomainName = derivedDomain
		if domainContext.DetectionMethod == "" {
			domainContext.DetectionMethod = "rootdse-defaultNamingContext"
		}
		if logger != nil {
			logger.Infof("ldap discovery: derived domain %s from pre-bind RootDSE", derivedDomain)
		}
	case currentDomain != derivedDomain && !strings.HasPrefix(domainContext.DetectionMethod, "cli-domain"):
		if logger != nil {
			logger.Infof("ldap discovery: overriding detected domain %s with RootDSE domain %s", currentDomain, derivedDomain)
		}
		domainContext.DomainName = derivedDomain
		domainContext.DetectionMethod = "rootdse-defaultNamingContext"
	}
	return rootDSE, nil
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

type bindCandidate struct {
	Label string
	Value string
}

func bindCandidates(username, domain string) []bindCandidate {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}

	if label := detectExplicitBindFormat(username); label != "" {
		return []bindCandidate{{Label: label, Value: username}}
	}

	candidates := []bindCandidate{{
		Label: "username",
		Value: username,
	}}

	if normalizedDomain := normalizeDetectedDomain(domain); normalizedDomain != "" {
		candidates = append(candidates, bindCandidate{
			Label: "UPN",
			Value: username + "@" + normalizedDomain,
		})
		if downLevel := downLevelBindDomain(normalizedDomain); downLevel != "" {
			candidates = append(candidates, bindCandidate{
				Label: "DOMAIN\\USER",
				Value: downLevel + `\` + username,
			})
		}
	}

	return deduplicateBindCandidates(candidates)
}

func detectExplicitBindFormat(username string) string {
	switch {
	case strings.Contains(username, "@"):
		return "explicit UPN"
	case strings.Contains(username, `\`):
		return "explicit DOMAIN\\USER"
	default:
		return ""
	}
}

func deduplicateBindCandidates(candidates []bindCandidate) []bindCandidate {
	seen := make(map[string]struct{}, len(candidates))
	deduped := make([]bindCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		value := strings.TrimSpace(candidate.Value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, bindCandidate{
			Label: candidate.Label,
			Value: value,
		})
	}
	return deduped
}

func domainFromNamingContext(namingContext string) string {
	if strings.TrimSpace(namingContext) == "" {
		return ""
	}

	parts := strings.Split(namingContext, ",")
	domainParts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 3 {
			continue
		}
		if !strings.EqualFold(part[:3], "dc=") {
			continue
		}
		value := normalizeDetectedDomain(part[3:])
		if value == "" {
			continue
		}
		domainParts = append(domainParts, value)
	}
	if len(domainParts) == 0 {
		return ""
	}
	return strings.Join(domainParts, ".")
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

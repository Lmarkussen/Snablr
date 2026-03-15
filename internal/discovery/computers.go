package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func queryComputerObjects(conn *ldap.Conn, baseDN string, pageSize uint32, logger Logger) ([]DiscoveredHost, error) {
	request := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"dNSHostName", "name", "operatingSystem", "distinguishedName"},
		nil,
	)

	result, err := conn.SearchWithPaging(request, pageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap discovery: computer search failed: %w", err)
	}

	hosts := make([]DiscoveredHost, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if entry == nil {
			continue
		}
		host := discoveredHostFromEntry(entry)
		if host.Hostname == "" && host.DNSHostname == "" {
			if logger != nil {
				logger.Debugf("ldap discovery: skipping computer object with no usable hostname: %s", entry.DN)
			}
			continue
		}
		hosts = append(hosts, host)
	}

	hosts = deduplicateHosts(hosts)
	sort.Slice(hosts, func(i, j int) bool {
		return preferredName(hosts[i]) < preferredName(hosts[j])
	})

	if logger != nil {
		logger.Infof("ldap discovery: discovered %d host(s)", len(hosts))
	}
	return hosts, nil
}

func discoveredHostFromEntry(entry *ldap.Entry) DiscoveredHost {
	dnsHost := strings.TrimSpace(entry.GetAttributeValue("dNSHostName"))
	name := strings.TrimSpace(entry.GetAttributeValue("name"))

	return DiscoveredHost{
		Hostname:          name,
		DNSHostname:       dnsHost,
		IP:                lookupIP(dnsHost, name),
		OperatingSystem:   strings.TrimSpace(entry.GetAttributeValue("operatingSystem")),
		DistinguishedName: strings.TrimSpace(entry.GetAttributeValue("distinguishedName")),
		Source:            "ldap",
	}
}

func deduplicateHosts(hosts []DiscoveredHost) []DiscoveredHost {
	out := make([]DiscoveredHost, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))

	for _, host := range hosts {
		key := discoveryKey(host)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, host)
	}

	return out
}

func discoveryKey(host DiscoveredHost) string {
	if host.DNSHostname != "" {
		return strings.ToLower(strings.TrimSpace(host.DNSHostname))
	}
	if host.Hostname != "" {
		return strings.ToLower(strings.TrimSpace(host.Hostname))
	}
	if host.IP != "" {
		return strings.ToLower(strings.TrimSpace(host.IP))
	}
	return ""
}

func preferredName(host DiscoveredHost) string {
	if host.DNSHostname != "" {
		return strings.ToLower(host.DNSHostname)
	}
	return strings.ToLower(host.Hostname)
}

func lookupIP(candidates ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		addresses, err := net.DefaultResolver.LookupHost(ctx, candidate)
		if err != nil || len(addresses) == 0 {
			continue
		}
		return addresses[0]
	}
	return ""
}

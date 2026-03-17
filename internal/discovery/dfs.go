package discovery

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var uncPattern = regexp.MustCompile(`\\\\[^\\/\s]+\\[^\\/\s]+(?:\\[^"\x00\r\n<>|?*]*)?`)

func DiscoverDFS(ctx context.Context, opts LDAPOptions, logger Logger) ([]DFSTarget, error) {
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
		return nil, fmt.Errorf("unable to determine a domain controller for dfs discovery")
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

	baseDN := strings.TrimSpace(domainContext.BaseDN)
	if baseDN == "" {
		baseDN = strings.TrimSpace(rootDSE.DefaultNamingContext)
	}
	if baseDN == "" {
		baseDN = strings.TrimSpace(rootDSE.RootNamingContext)
	}
	if baseDN == "" {
		return nil, fmt.Errorf("dfs discovery: rootDSE did not return a naming context")
	}

	if logger != nil {
		logger.Infof("dfs discovery: searching base DN %s using %s", baseDN, session.AuthMethod)
	}

	return queryDFSTargets(session.Conn, baseDN, opts.PageSize, logger)
}

func queryDFSTargets(conn *ldap.Conn, baseDN string, pageSize uint32, logger Logger) ([]DFSTarget, error) {
	request := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(objectClass=msDFS-Linkv2)(objectClass=fTDfs)(msDFS-TargetListv2=*)(remoteServerName=*))",
		[]string{"cn", "name", "distinguishedName", "remoteServerName", "msDFS-LinkPathv2", "msDFS-TargetListv2"},
		nil,
	)

	result, err := conn.SearchWithPaging(request, pageSize)
	if err != nil {
		return nil, fmt.Errorf("dfs discovery: dfs search failed: %w", err)
	}

	targets := make([]DFSTarget, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if entry == nil {
			continue
		}
		entryTargets := dfsTargetsFromEntry(entry)
		if len(entryTargets) == 0 {
			if logger != nil {
				logger.Debugf("dfs discovery: skipping entry without usable dfs targets: %s", entry.DN)
			}
			continue
		}
		targets = append(targets, entryTargets...)
	}

	targets = deduplicateDFSTargets(targets)
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].TargetServer == targets[j].TargetServer {
			if targets[i].TargetShare == targets[j].TargetShare {
				return targets[i].NamespacePath < targets[j].NamespacePath
			}
			return targets[i].TargetShare < targets[j].TargetShare
		}
		return targets[i].TargetServer < targets[j].TargetServer
	})

	if logger != nil {
		logger.Infof("dfs discovery: discovered %d dfs target(s)", len(targets))
		for _, target := range targets {
			logger.Debugf("dfs discovery: namespace=%s target=%s/%s link=%s", target.NamespacePath, target.TargetServer, target.TargetShare, target.LinkPath)
		}
	}

	return targets, nil
}

func dfsTargetsFromEntry(entry *ldap.Entry) []DFSTarget {
	namespacePath := bestNamespacePath(entry)
	linkPath := bestLinkPath(entry)
	rawPaths := collectDFSUNCs(entry)
	if len(rawPaths) == 0 {
		return nil
	}

	targets := make([]DFSTarget, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		server, share, path := parseUNC(rawPath)
		if server == "" || share == "" {
			continue
		}

		resolvedLink := linkPath
		if resolvedLink == "" {
			resolvedLink = path
		}

		targets = append(targets, DFSTarget{
			NamespacePath: namespacePath,
			TargetServer:  server,
			TargetShare:   share,
			LinkPath:      normalizeDFSPath(resolvedLink),
			Source:        "dfs",
		})
	}

	return targets
}

func bestNamespacePath(entry *ldap.Entry) string {
	values := append([]string{}, entry.GetAttributeValues("remoteServerName")...)
	values = append(values, entry.GetAttributeValues("msDFS-LinkPathv2")...)
	for _, value := range values {
		for _, unc := range uncPattern.FindAllString(value, -1) {
			server, share, _ := parseUNC(unc)
			if server == "" || share == "" {
				continue
			}
			return `\\` + server + `\` + share
		}
	}

	linkPath := bestLinkPath(entry)
	if linkPath == "" {
		linkPath = strings.TrimSpace(entry.GetAttributeValue("name"))
	}
	return normalizeDFSPath(linkPath)
}

func bestLinkPath(entry *ldap.Entry) string {
	for _, value := range entry.GetAttributeValues("msDFS-LinkPathv2") {
		value = normalizeDFSPath(value)
		if value != "" {
			return value
		}
	}

	name := strings.TrimSpace(entry.GetAttributeValue("name"))
	if name == "" {
		name = strings.TrimSpace(entry.GetAttributeValue("cn"))
	}
	return normalizeDFSPath(name)
}

func collectDFSUNCs(entry *ldap.Entry) []string {
	var values []string
	values = append(values, entry.GetAttributeValues("remoteServerName")...)
	for _, raw := range entry.GetRawAttributeValues("msDFS-TargetListv2") {
		if len(raw) == 0 {
			continue
		}
		values = append(values, string(raw))
	}

	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, value := range values {
		for _, match := range uncPattern.FindAllString(value, -1) {
			server, share, path := parseUNC(match)
			if server == "" || share == "" {
				continue
			}

			key := strings.ToLower(server + `\` + share + `\` + path)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, `\\`+server+`\`+share+normalizeDFSPath(path))
		}
	}

	return out
}

func parseUNC(value string) (server, share, path string) {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if !strings.HasPrefix(value, `\\`) {
		return "", "", ""
	}

	trimmed := strings.TrimPrefix(value, `\\`)
	parts := strings.Split(trimmed, `\`)
	if len(parts) < 2 {
		return "", "", ""
	}

	server = strings.TrimSpace(parts[0])
	share = strings.TrimSpace(parts[1])
	if len(parts) > 2 {
		path = strings.Join(parts[2:], "/")
	}

	return server, share, normalizeDFSPath(path)
}

func normalizeDFSPath(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.ReplaceAll(value, `\`, `/`)
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimPrefix(value, "/")
	return value
}

func deduplicateDFSTargets(targets []DFSTarget) []DFSTarget {
	out := make([]DFSTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))

	for _, target := range targets {
		key := strings.ToLower(strings.Join([]string{
			target.NamespacePath,
			target.TargetServer,
			target.TargetShare,
			target.LinkPath,
		}, "::"))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, target)
	}

	return out
}

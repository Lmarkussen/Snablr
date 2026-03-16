package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func DetectDomainContext(ctx context.Context, opts LDAPOptions, logger Logger) (DomainContext, error) {
	context := DomainContext{
		DomainName:       normalizeDetectedDomain(opts.Domain),
		DomainController: strings.TrimSpace(opts.DomainController),
		BaseDN:           strings.TrimSpace(opts.BaseDN),
	}

	if context.DomainName != "" {
		context.DetectionMethod = "cli-domain"
		logDomainContext(logger, context)
	} else if domain, method := detectDomainFromEnvironment(); domain != "" {
		context.DomainName = domain
		context.DetectionMethod = method
		logDomainContext(logger, context)
	} else if domain, method := detectDomainFromHostname(ctx); domain != "" {
		context.DomainName = domain
		context.DetectionMethod = method
		logDomainContext(logger, context)
	} else if domain, method := detectDomainFromResolvConf(); domain != "" {
		context.DomainName = domain
		context.DetectionMethod = method
		logDomainContext(logger, context)
	} else if domain, dc := detectDomainBySRV(ctx, logger); domain != "" {
		context.DomainName = domain
		context.DomainController = dc
		context.DetectionMethod = "dns-srv-fallback"
		logDomainContext(logger, context)
	}

	if context.DomainController != "" {
		if context.DetectionMethod == "" && context.DomainName != "" {
			context.DetectionMethod = "cli-domain+cli-dc"
		} else if context.DetectionMethod == "" {
			context.DetectionMethod = "cli-dc"
		}
		logDomainContext(logger, context)
		return context, nil
	}

	if context.DomainName != "" {
		dc, err := locateDomainController(ctx, context.DomainName, logger)
		if err == nil {
			context.DomainController = dc
			if context.DetectionMethod == "" {
				context.DetectionMethod = "dns-srv"
			}
			logDomainContext(logger, context)
			return context, nil
		}
		if logger != nil {
			logger.Warnf("ldap discovery: srv lookup failed for detected domain %s: %v", context.DomainName, err)
		}
	}

	if context.DomainName == "" && context.DomainController == "" {
		return DomainContext{}, fmt.Errorf("unable to determine domain context")
	}
	return context, nil
}

func locateDomainController(ctx context.Context, domain string, logger Logger) (string, error) {
	_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return "", fmt.Errorf("srv lookup for domain controllers in %s failed: %w", domain, err)
	}
	if len(records) == 0 {
		return "", fmt.Errorf("no domain controllers returned for %s", domain)
	}

	target := strings.TrimSuffix(records[0].Target, ".")
	if logger != nil {
		logger.Infof("ldap discovery: selected domain controller %s via DNS SRV", target)
	}
	return target, nil
}

func detectDomainFromEnvironment() (string, string) {
	candidates := []struct {
		method string
		value  string
	}{
		{method: "env:USERDNSDOMAIN", value: os.Getenv("USERDNSDOMAIN")},
		{method: "env:USERDOMAIN_FQDN", value: os.Getenv("USERDOMAIN_FQDN")},
		{method: "env:DNSDOMAIN", value: os.Getenv("DNSDOMAIN")},
		{method: "env:USERDOMAIN", value: os.Getenv("USERDOMAIN")},
	}
	for _, candidate := range candidates {
		if domain := normalizeDetectedDomain(candidate.value); domain != "" {
			return domain, candidate.method
		}
	}
	return "", ""
}

func detectDomainFromHostname(ctx context.Context) (string, string) {
	if domain := detectDomainFromHostnameCommand(ctx, "-d"); domain != "" {
		return domain, "hostname -d"
	}
	if domain := detectDomainFromHostnameCommand(ctx, "-f"); domain != "" {
		return domain, "hostname -f"
	}
	if domain := detectDomainFromHostnameCommand(ctx); domain != "" {
		return domain, "hostname"
	}
	if domain := detectDomainFromHostnameSuffix(); domain != "" {
		return domain, "os.Hostname"
	}
	return "", ""
}

func detectDomainFromHostnameCommand(ctx context.Context, args ...string) string {
	path, err := exec.LookPath("hostname")
	if err != nil {
		return ""
	}

	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil {
		return ""
	}

	value := strings.TrimSpace(string(out))
	if value == "" {
		return ""
	}

	normalized := normalizeDetectedDomain(value)
	if len(args) == 0 {
		if idx := strings.Index(normalized, "."); idx > 0 && idx+1 < len(normalized) {
			return normalizeDetectedDomain(normalized[idx+1:])
		}
		return ""
	}

	if idx := strings.Index(normalized, "."); idx > 0 && idx+1 < len(normalized) {
		switch args[0] {
		case "-f":
			return normalizeDetectedDomain(normalized[idx+1:])
		case "-d":
			return normalized
		}
	}
	if args[0] == "-f" {
		return ""
	}
	return normalized
}

func detectDomainFromHostnameSuffix() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	if idx := strings.Index(hostname, "."); idx > 0 && idx+1 < len(hostname) {
		return normalizeDetectedDomain(hostname[idx+1:])
	}
	return ""
}

func detectDomainFromResolvConf() (string, string) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "search "):
			for _, field := range strings.Fields(strings.TrimPrefix(line, "search ")) {
				if domain := normalizeDetectedDomain(field); domain != "" {
					return domain, "resolv.conf search"
				}
			}
		case strings.HasPrefix(line, "domain "):
			if domain := normalizeDetectedDomain(strings.TrimPrefix(line, "domain ")); domain != "" {
				return domain, "resolv.conf domain"
			}
		}
	}
	return "", ""
}

func detectDomainBySRV(ctx context.Context, logger Logger) (string, string) {
	for _, candidate := range srvDiscoveryCandidates() {
		dc, err := locateDomainController(ctx, candidate, logger)
		if err != nil {
			continue
		}
		return candidate, dc
	}
	return "", ""
}

func srvDiscoveryCandidates() []string {
	seen := make(map[string]struct{})
	candidates := make([]string, 0, 6)

	add := func(value string) {
		value = normalizeDetectedDomain(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	add(os.Getenv("USERDNSDOMAIN"))
	add(os.Getenv("USERDOMAIN"))
	add(detectDomainFromHostnameSuffix())

	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "search ") {
				for _, field := range strings.Fields(strings.TrimPrefix(line, "search ")) {
					add(field)
				}
			}
			if strings.HasPrefix(line, "domain ") {
				add(strings.TrimPrefix(line, "domain "))
			}
		}
	}

	return candidates
}

func normalizeDetectedDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
	if value == "" {
		return ""
	}
	if strings.Contains(value, " ") {
		return ""
	}
	switch value {
	case "(none)", "none":
		return ""
	}
	if strings.ContainsAny(value, "()") {
		return ""
	}
	return value
}

func downLevelBindDomain(domain string) string {
	domain = normalizeDetectedDomain(domain)
	if domain == "" {
		return ""
	}
	if idx := strings.Index(domain, "."); idx > 0 {
		domain = domain[:idx]
	}
	return strings.ToUpper(domain)
}

func logDomainContext(logger Logger, context DomainContext) {
	if logger == nil || context.DetectionMethod == "" {
		return
	}
	logger.Infof("ldap discovery: domain context method=%s domain=%s dc=%s", context.DetectionMethod, valueOrUnknown(context.DomainName), valueOrUnknown(context.DomainController))
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "<unknown>"
	}
	return value
}

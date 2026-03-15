package discovery

import "time"

type DiscoveredHost struct {
	Hostname          string
	DNSHostname       string
	IP                string
	OperatingSystem   string
	DistinguishedName string
	Source            string
}

type Target struct {
	Input        string
	Hostname     string
	IP           string
	Reachable445 bool
	Source       string
}

type TargetStats struct {
	Loaded      int
	Unique      int
	Reachable   int
	Skipped     int
	Unreachable int
}

type DomainContext struct {
	DomainName       string
	DomainController string
	BaseDN           string
	DetectionMethod  string
}

type LDAPOptions struct {
	Username         string
	Password         string
	Domain           string
	DomainController string
	BaseDN           string
	Timeout          time.Duration
	PageSize         uint32
}

type Logger interface {
	Debugf(string, ...any)
	Infof(string, ...any)
	Warnf(string, ...any)
}

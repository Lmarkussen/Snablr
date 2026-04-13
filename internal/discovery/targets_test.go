package discovery

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"snablr/internal/config"
)

type captureLogger struct {
	lines []string
}

func (l *captureLogger) Debugf(format string, args ...any) {}
func (l *captureLogger) Infof(format string, args ...any) {
	l.lines = append(l.lines, sprintf(format, args...))
}
func (l *captureLogger) Warnf(format string, args ...any) {
	l.lines = append(l.lines, sprintf(format, args...))
}

func sprintf(format string, args ...any) string {
	return strings.TrimSpace(fmt.Sprintf(format, args...))
}

func TestDeduplicateTargets(t *testing.T) {
	t.Parallel()

	input := []Target{
		{Hostname: "FS01", Source: "cli"},
		{Hostname: "fs01", Source: "file"},
		{IP: "10.0.0.5", Source: "ldap"},
		{IP: "10.0.0.5", Source: "dfs"},
		{Input: "fileserver", Source: "file"},
	}

	got := deduplicateTargets(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique targets, got %d: %#v", len(got), got)
	}
}

func TestNewLDAPTargetPrefersDNSHostname(t *testing.T) {
	t.Parallel()

	target := newLDAPTarget(DiscoveredHost{
		Hostname:    "FS01",
		DNSHostname: "fs01.example.local",
		IP:          "10.0.0.10",
		Source:      "ldap",
	})

	if target.Hostname != "fs01.example.local" {
		t.Fatalf("expected DNS hostname, got %#v", target)
	}
	if target.IP != "10.0.0.10" {
		t.Fatalf("expected IP to be preserved, got %#v", target)
	}
}

func TestResolveLogsStartupPhasesForExplicitTargets(t *testing.T) {
	t.Parallel()

	logger := &captureLogger{}
	_, err := Resolve(context.Background(), config.ScanConfig{
		Targets:               []string{"10.0.0.5"},
		SkipReachabilityCheck: true,
	}, logger, nil)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	joined := strings.Join(logger.lines, "\n")
	for _, want := range []string{
		"starting target discovery",
		"using 1 explicit target(s) from CLI",
		"resolved 1 candidate target(s) before deduplication",
		"prepared 1 unique target(s) for reachability checks",
		"reachability checks skipped; marking 1 target(s) as reachable",
		"target discovery complete: 1 reachable, 0 skipped",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected resolve logs to contain %q, got %q", want, joined)
		}
	}
}

package discovery

import (
	"context"
	"testing"
)

func TestFilterReachableSkipCheckMarksTargetsReachable(t *testing.T) {
	t.Parallel()

	targets := []Target{
		{Input: "127.0.0.1", Hostname: "127.0.0.1", Source: "cli"},
		{Input: "192.0.2.10", IP: "192.0.2.10", Source: "file"},
	}

	all, reachable, err := FilterReachable(context.Background(), targets, ReachabilityOptions{
		SkipCheck: true,
		Workers:   2,
	}, nil, nil)
	if err != nil {
		t.Fatalf("FilterReachable returned error: %v", err)
	}

	if len(all) != 2 || len(reachable) != 2 {
		t.Fatalf("expected all targets to be reachable, got all=%d reachable=%d", len(all), len(reachable))
	}
	for _, target := range reachable {
		if !target.Reachable445 {
			t.Fatalf("expected target to be marked reachable: %#v", target)
		}
	}
}

func TestTargetAddressPrefersIP(t *testing.T) {
	t.Parallel()

	target := Target{IP: "10.0.0.5", Hostname: "fs01", Input: "ignored"}
	if got := targetAddress(target); got != "10.0.0.5" {
		t.Fatalf("expected IP address, got %q", got)
	}
}

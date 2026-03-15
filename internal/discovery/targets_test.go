package discovery

import "testing"

func TestDeduplicateTargets(t *testing.T) {
	t.Parallel()

	input := []Target{
		{Hostname: "FILESERVER01", Source: "cli"},
		{Hostname: "fileserver01", Source: "file"},
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
		Hostname:    "FILESERVER01",
		DNSHostname: "fileserver01.example.local",
		IP:          "10.0.0.10",
		Source:      "ldap",
	})

	if target.Hostname != "fileserver01.example.local" {
		t.Fatalf("expected DNS hostname, got %#v", target)
	}
	if target.IP != "10.0.0.10" {
		t.Fatalf("expected IP to be preserved, got %#v", target)
	}
}

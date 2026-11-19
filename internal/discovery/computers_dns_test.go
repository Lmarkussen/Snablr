package discovery

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Discovered computers are resolved concurrently, bounded, and every host
// gets the address of its own names (DNS hostname first, then name).
func TestResolveDiscoveredIPsConcurrentAndOrdered(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	orig := lookupIPFunc
	defer func() { lookupIPFunc = orig }()
	lookupIPFunc = func(candidates ...string) string {
		mu.Lock()
		active++
		maxActive = max(maxActive, active)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		for _, candidate := range candidates {
			if candidate != "" {
				return "192.0.2." + candidate[len(candidate)-2:]
			}
		}
		return ""
	}

	hosts := make([]DiscoveredHost, 64)
	for i := range hosts {
		hosts[i] = DiscoveredHost{Hostname: fmt.Sprintf("host%02d", i)}
		if i%2 == 0 {
			hosts[i].DNSHostname = fmt.Sprintf("host%02d.example.test.%02d", i, i)
		}
	}
	start := time.Now()
	resolveDiscoveredIPs(hosts)
	elapsed := time.Since(start)

	for i, host := range hosts {
		if want := fmt.Sprintf("192.0.2.%02d", i); host.IP != want {
			t.Fatalf("host %d resolved to %q, want %q", i, host.IP, want)
		}
	}
	if maxActive < 2 || maxActive > discoveryDNSWorkers {
		t.Fatalf("max concurrent lookups=%d, want overlap bounded by %d", maxActive, discoveryDNSWorkers)
	}
	if sequential := 64 * 20 * time.Millisecond; elapsed > sequential/2 {
		t.Fatalf("resolving took %s, sequential would take %s", elapsed, sequential)
	}
}

package smb

import (
	"context"
	"testing"
	"time"
)

func TestPacerSpacesOperations(t *testing.T) {
	p := newPacer()
	var slept []time.Duration
	p.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	p.jitter = func(min, max time.Duration) time.Duration { return max }

	// Disabled: no waits.
	for i := 0; i < 3; i++ {
		if err := p.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(slept) != 0 {
		t.Fatalf("unpaced client slept: %v", slept)
	}

	p.set(Pacing{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond})
	for i := 0; i < 3; i++ {
		_ = p.wait(context.Background())
	}
	if len(slept) != 3 {
		t.Fatalf("paced operations slept %d times, want 3", len(slept))
	}
	for _, d := range slept {
		if d <= 0 || d > 50*time.Millisecond {
			t.Errorf("delay %v outside the range", d)
		}
	}
}

func TestPacerStopsOnCancel(t *testing.T) {
	p := newPacer()
	p.set(Pacing{Min: time.Hour, Max: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.wait(ctx); err == nil {
		t.Error("cancelled wait returned no error")
	}
}

func TestRandomBetweenStaysInRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := randomBetween(500*time.Millisecond, 2*time.Second)
		if d < 500*time.Millisecond || d > 2*time.Second {
			t.Fatalf("delay %v outside 500ms-2s", d)
		}
	}
}

// Paced walks list one directory at a time; unpaced walks keep prefetching.
func TestPacedWalkDoesNotPrefetch(t *testing.T) {
	c := NewClient()
	if c.walkPrefetch() != dirPrefetchInFlight {
		t.Errorf("unpaced prefetch = %d", c.walkPrefetch())
	}
	c.SetPacing(Pacing{Min: time.Millisecond, Max: 2 * time.Millisecond})
	if c.walkPrefetch() != 0 {
		t.Errorf("paced prefetch = %d", c.walkPrefetch())
	}
}

func TestNTLMWorkstationName(t *testing.T) {
	if got := newNTLMInitiator(Auth{Mode: AuthModePassword, Workstation: " WS-0142 "}, "user", "CORP").Workstation; got != "WS-0142" {
		t.Errorf("workstation %q", got)
	}
	if got := newNTLMInitiator(Auth{Mode: AuthModePassword}, "user", "CORP").Workstation; got != "" {
		t.Errorf("default workstation %q, want empty as before", got)
	}
}

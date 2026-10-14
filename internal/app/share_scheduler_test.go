package app

import (
	"sync"
	"testing"

	"snablr/internal/planner"
)

func syntheticSharePlans() []planner.PlannedTarget {
	return []planner.PlannedTarget{
		{Host: "host-a", Share: "A"},
		{Host: "host-a", Share: "B"},
		{Host: "host-a", Share: "C"},
		{Host: "host-a", Share: "D"},
	}
}

func nextShareName(t *testing.T, scheduler *shareScheduler) string {
	t.Helper()
	plan, ok := scheduler.next()
	if !ok {
		t.Fatal("expected another share")
	}
	return plan.Share
}

func TestShareSchedulerDefersCurrentShareToEnd(t *testing.T) {
	scheduler := newShareScheduler(syntheticSharePlans())
	if got := nextShareName(t, scheduler); got != "A" {
		t.Fatalf("first share = %q, want A", got)
	}
	scheduler.complete()
	if got := nextShareName(t, scheduler); got != "B" {
		t.Fatalf("second share = %q, want B", got)
	}
	if got := scheduler.requestDefer(); got != "Deferred B to end of queue" {
		t.Fatalf("defer message = %q", got)
	}
	plan, _ := scheduler.next()
	if !scheduler.consumeDefer(plan) {
		t.Fatal("expected defer boundary to be consumed")
	}
	if got := nextShareName(t, scheduler); got != "C" {
		t.Fatalf("next share after deferring B = %q, want C", got)
	}
}

func TestShareSchedulerMultipleDeferralsAreDeterministic(t *testing.T) {
	scheduler := newShareScheduler(syntheticSharePlans())
	_, _ = scheduler.next()
	scheduler.complete()
	_, _ = scheduler.next()
	scheduler.requestDefer()
	plan, _ := scheduler.next()
	scheduler.consumeDefer(plan)
	_, _ = scheduler.next()
	if got := scheduler.requestDefer(); got != "Deferred C to end of queue" {
		t.Fatalf("defer C message = %q", got)
	}
	plan, _ = scheduler.next()
	scheduler.consumeDefer(plan)
	for _, want := range []string{"D", "B", "C"} {
		if got := nextShareName(t, scheduler); got != want {
			t.Fatalf("share order = %q, want %q", got, want)
		}
		scheduler.complete()
	}
}

func TestShareSchedulerIdentityIncludesHost(t *testing.T) {
	scheduler := newShareScheduler([]planner.PlannedTarget{
		{Host: "host-a", Share: "Data"},
		{Host: "host-b", Share: "Data"},
	})
	first, _ := scheduler.next()
	if first.Host != "host-a" {
		t.Fatalf("first host = %q", first.Host)
	}
	if got := scheduler.requestDefer(); got != "Deferred Data to end of queue" {
		t.Fatalf("unexpected defer message: %q", got)
	}
	scheduler.consumeDefer(first)
	second, _ := scheduler.next()
	if second.Host != "host-b" {
		t.Fatalf("second host = %q", second.Host)
	}
}

func TestShareSchedulerAlreadyLastAndSingleShareAreSafe(t *testing.T) {
	for _, plans := range [][]planner.PlannedTarget{
		{{Host: "host-a", Share: "only"}},
		{{Host: "host-a", Share: "A"}, {Host: "host-a", Share: "B"}},
	} {
		scheduler := newShareScheduler(plans)
		first, _ := scheduler.next()
		if len(plans) == 1 {
			if got := scheduler.requestDefer(); got != "only is already the last remaining share" {
				t.Fatalf("single-share message = %q", got)
			}
			continue
		}
		if got := scheduler.requestDefer(); got != "Deferred A to end of queue" {
			t.Fatalf("first defer message = %q", got)
		}
		if !scheduler.consumeDefer(first) {
			t.Fatal("expected first defer boundary")
		}
		second, _ := scheduler.next()
		if second.Share != "B" {
			t.Fatalf("current share = %q", second.Share)
		}
		scheduler.complete()
		last, _ := scheduler.next()
		if got := scheduler.requestDefer(); got != "A is already the last remaining share" {
			t.Fatalf("last-share message = %q", got)
		}
		if last.Share != "A" {
			t.Fatalf("last share = %q", last.Share)
		}
	}
}

func TestShareSchedulerCompletedShareIsNotRequeued(t *testing.T) {
	scheduler := newShareScheduler(syntheticSharePlans()[:2])
	_, _ = scheduler.next()
	scheduler.complete()
	if got := nextShareName(t, scheduler); got != "B" {
		t.Fatalf("next share = %q", got)
	}
	scheduler.complete()
	if _, ok := scheduler.next(); ok {
		t.Fatal("completed shares were requeued")
	}
}

func TestShareSchedulerConcurrentDeferAndSnapshot(t *testing.T) {
	scheduler := newShareScheduler(syntheticSharePlans())
	_, _ = scheduler.next()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = scheduler.requestDefer()
			_ = scheduler.snapshot()
		}()
	}
	wg.Wait()
}

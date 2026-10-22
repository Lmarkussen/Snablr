package app

import (
	"testing"

	"snablr/internal/store"
)

func TestClassifyScanStatus(t *testing.T) {
	tests := []struct {
		name                         string
		timedOut, interrupted        bool
		persistenceFailed, runFailed bool
		completed, skipped           int
		want                         store.Status
	}{
		{name: "completed", want: store.StatusCompleted},
		{name: "completed with skips", skipped: 2, want: store.StatusCompletedWithSkips},
		{name: "partial after share error", runFailed: true, completed: 1, want: store.StatusPartial},
		{name: "failed before meaningful work", runFailed: true, want: store.StatusFailed},
		{name: "timed out", timedOut: true, runFailed: true, completed: 1, want: store.StatusTimedOut},
		{name: "interrupted", interrupted: true, runFailed: true, completed: 1, want: store.StatusInterrupted},
		{name: "persistence failure", persistenceFailed: true, skipped: 1, want: store.StatusFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyScanStatus(test.timedOut, test.interrupted, test.persistenceFailed, test.runFailed, test.completed, test.skipped)
			if got != test.want {
				t.Fatalf("status=%q, want %q", got, test.want)
			}
		})
	}
}

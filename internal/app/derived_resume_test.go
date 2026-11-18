package app

import (
	"context"
	"path/filepath"
	"testing"

	"snablr/internal/store"
)

// A resumed or reused scan adds findings to an existing scan ID. Its derived
// correlation generation must be invalidated so the end-of-run report path
// rebuilds cross-file correlations over the complete finding population.
func TestContinuedScanInvalidatesPublishedDerivedCorrelations(t *testing.T) {
	cases := []struct {
		name      string
		resume    *store.ResumeState
		wantReady bool
	}{
		{name: "resumed or reused scan", resume: &store.ResumeState{}, wantReady: false},
		{name: "fresh scan", resume: nil, wantReady: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shadow, err := store.Open(filepath.Join(t.TempDir(), "state.db"), store.Options{ScanID: "derived-resume", BatchSize: 1, QueueSize: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer shadow.Close()
			if err := shadow.ResetCorrelationState(); err != nil {
				t.Fatal(err)
			}
			if err := shadow.CompleteCorrelationState(); err != nil {
				t.Fatal(err)
			}
			if err := shadow.Flush(); err != nil {
				t.Fatal(err)
			}

			if err := invalidateDerivedCorrelationsForContinuedScan(shadow, tc.resume); err != nil {
				t.Fatal(err)
			}
			if err := shadow.Flush(); err != nil {
				t.Fatal(err)
			}
			ready, err := shadow.CorrelationStateReady(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if ready != tc.wantReady {
				t.Fatalf("derived correlation state ready=%v, want %v", ready, tc.wantReady)
			}
		})
	}
}

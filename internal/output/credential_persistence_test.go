package output

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"snablr/internal/config"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

// A scan run with --no-outfile uses the live console or TUI writer as its only
// sink. Harvested credential candidates must still reach SQLite so Finder can
// investigate them; previously they were silently dropped.
func TestCredentialCandidatesPersistWithoutReportOutputs(t *testing.T) {
	cases := []struct {
		name string
		wrap func(scanner.FindingSink) scanner.FindingSink
	}{
		{name: "bare console sink", wrap: func(sink scanner.FindingSink) scanner.FindingSink { return sink }},
		{name: "console sink with suppression rules", wrap: func(sink scanner.FindingSink) scanner.FindingSink {
			return WrapWithSuppression(sink, config.SuppressionConfig{Rules: []config.SuppressionRule{{
				ID: "synthetic-suppression", Enabled: true, RuleIDs: []string{"content.synthetic_unrelated"},
			}}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, err := store.Open(filepath.Join(t.TempDir(), "state.db"), store.Options{ScanID: "no-outfile-credentials", BatchSize: 1, QueueSize: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()

			var console bytes.Buffer
			sink := tc.wrap(NewConsoleWriter(&console, nil))
			AttachSQLiteStore(sink, state)

			recorder := CredentialCandidateRecorder(sink)
			if recorder == nil {
				t.Fatal("no credential candidate recorder for a SQLite-attached sink")
			}
			candidate := credentialanalysis.Candidate{
				Verification: credentialanalysis.Confirmed, CredentialType: "password",
				Identity: "svc_synthetic", Value: "SYNTHETIC_VALUE_001",
				Host: "synthetic-host", Share: "SyntheticShare", Path: "configs/app.config",
			}
			if err := recorder.RecordCredentialCandidate(candidate); err != nil {
				t.Fatal(err)
			}
			if err := state.Flush(); err != nil {
				t.Fatal(err)
			}
			var persisted int
			if err := state.IterateCredentials(context.Background(), 16, func(batch []credentialanalysis.Candidate) error {
				persisted += len(batch)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if persisted != 1 {
				t.Fatalf("persisted credential candidates=%d, want 1", persisted)
			}
		})
	}
}

func TestCredentialCandidateRecorderWithoutStoreOrRecorderIsNil(t *testing.T) {
	var console bytes.Buffer
	if recorder := CredentialCandidateRecorder(NewConsoleWriter(&console, nil)); recorder != nil {
		t.Fatalf("unattached console sink returned recorder %T", recorder)
	}
}

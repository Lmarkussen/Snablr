package findings

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

func TestProviderRehydratesCloudObservationWithEvidenceAndIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.db")
	state, err := store.Open(path, store.Options{ScanID: "p5-cloud", SnablrVersion: "test", Semantics: "p5", QueueSize: 8, BatchSize: 1, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	want := scanner.Finding{
		RuleID: "cloudinspect.gcp.external_account", RuleName: "Google Cloud External Account Configuration",
		Category: "cloud", SignalType: "validated", Confidence: "high", Host: "host-a", Share: "share-a",
		FilePath: "configs/opaque", MatchedText: `{"type":"external_account"}`, Context: `{"type":"external_account"}`,
		ObservationID: "cloudinspect:stable-synthetic-observation", Tags: []string{"cloud", "gcp", "gcp:type:external-account"},
	}
	if err := state.RecordFinding(want); err != nil {
		t.Fatal(err)
	}
	if err := state.SetScanStatus(store.StatusCompleted, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := provider.Findings(context.Background(), "p5-cloud", 0, 10)
	if err != nil {
		_ = provider.Close()
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Finding.MatchedText != want.MatchedText || items[0].Finding.Context != want.Context || items[0].Finding.ObservationID != want.ObservationID || items[0].Finding.Host != want.Host || items[0].Finding.Share != want.Share {
		t.Fatalf("cloud observation did not rehydrate exactly: got %#v", items)
	}
	categories := buildCategories(nil, items, nil)
	if len(categories) != 1 || categories[0].Name != "Application & Cloud Secrets" || len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "Secret References & Configuration Artifacts" {
		t.Fatalf("rehydrated cloud observation did not retain Finder mapping: %#v", categories)
	}
}

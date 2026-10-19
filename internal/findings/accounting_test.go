package findings

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/store"
)

func accountingCredential(key, typ, identity, value, path string, verification credentialanalysis.Verification) Credential {
	return Credential{
		CredentialKey: key,
		Candidate: credentialanalysis.Candidate{
			CredentialType: typ,
			Identity:       identity,
			Value:          value,
			Path:           path,
			Host:           "HOST",
			Share:          "Share",
			Verification:   verification,
		},
	}
}

func TestCredentialProjectionAccountingReconcilesGroupedAndDistinctRows(t *testing.T) {
	credentials := []Credential{
		accountingCredential("pair-a", "password", "DOMAIN\\alice", "same", "a.ini", credentialanalysis.Confirmed),
		accountingCredential("pair-b", "password", "DOMAIN\\alice", "same", "b.ini", credentialanalysis.Confirmed),
		accountingCredential("pair-c", "password", "DOMAIN\\bob", "same", "c.ini", credentialanalysis.Confirmed),
		accountingCredential("review", "password", "", "", "review.ini", credentialanalysis.Review),
		accountingCredential("hash", "nt_hash", "DOMAIN\\alice", "00112233445566778899aabbccddeeff", "hash.txt", credentialanalysis.Confirmed),
	}
	categories, audit := buildCategoriesWithAccounting("scan-one", credentials, nil, nil)
	if audit.TotalPersistedRows != 5 || audit.UnaccountedRows != 0 {
		t.Fatalf("unexpected accounting: %#v", audit)
	}
	if audit.PresentedRows != 4 || audit.GroupedRows != 1 {
		t.Fatalf("want four representatives and one grouped row: %#v", audit)
	}
	if audit.LogicalDiscoveryCount != 4 {
		t.Fatalf("logical discoveries = %d, want 4", audit.LogicalDiscoveryCount)
	}
	if len(categories) == 0 {
		t.Fatal("expected categories")
	}
	var aliceSources int
	for _, group := range categories {
		for _, discovery := range group.Discoveries {
			if discovery.Identity == "DOMAIN\\alice" && discovery.Value == "same" {
				aliceSources = len(discovery.PersistedRefs)
			}
		}
	}
	if aliceSources != 2 {
		t.Fatalf("grouped source rows = %d, want 2", aliceSources)
	}
}

func TestCredentialProjectionAccountingDetectsDeliberateOmission(t *testing.T) {
	credentials := []Credential{
		accountingCredential("one", "password", "user-one", "one", "one.ini", credentialanalysis.Confirmed),
		accountingCredential("two", "password", "user-two", "two", "two.ini", credentialanalysis.Confirmed),
	}
	categories, _ := buildCategoriesWithAccounting("scan-one", credentials, nil, nil)
	for index := range categories {
		for discovery := range categories[index].Discoveries {
			if len(categories[index].Discoveries[discovery].PersistedRefs) > 0 {
				categories[index].Discoveries[discovery].PersistedRefs = categories[index].Discoveries[discovery].PersistedRefs[:1]
				break
			}
		}
	}
	// Remove one entire discovery's trace, simulating a projection omission.
	for index := range categories {
		for discovery := range categories[index].Discoveries {
			if len(categories[index].Discoveries[discovery].PersistedRefs) > 0 {
				categories[index].Discoveries[discovery].PersistedRefs = nil
				audit := auditCredentialProjection("scan-one", credentials, categories)
				if audit.UnaccountedRows != 1 || len(audit.UnaccountedRefs) != 1 || audit.UnaccountedRefs[0] != "one" && audit.UnaccountedRefs[0] != "two" {
					t.Fatalf("omission was not detected: %#v", audit)
				}
				return
			}
		}
	}
	t.Fatal("test setup did not find a credential discovery")
}

func TestReadAllCredentialsTraversesMoreThanOnePage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "many.db")
	state, err := store.Open(path, store.Options{ScanID: "scan-many", SnablrVersion: "test", Semantics: "synthetic", QueueSize: 32, BatchSize: 16, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < PageSize+1; index++ {
		candidate := credentialanalysis.Candidate{CredentialType: "password", Identity: fmt.Sprintf("user-%04d", index), Value: fmt.Sprintf("value-%04d", index), Path: fmt.Sprintf("%04d.ini", index), Verification: credentialanalysis.Confirmed}
		if err := state.RecordCredential(candidate); err != nil {
			t.Fatal(err)
		}
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
	defer provider.Close()
	credentials, err := readAllCredentials(context.Background(), provider, "scan-many")
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != PageSize+1 {
		t.Fatalf("read %d credentials, want %d", len(credentials), PageSize+1)
	}
	_, audit := buildCategoriesWithAccounting("scan-many", credentials, nil, nil)
	if audit.UnaccountedRows != 0 || audit.TotalPersistedRows != PageSize+1 {
		t.Fatalf("multi-page accounting failed: %#v", audit)
	}
}

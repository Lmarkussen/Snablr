package findings

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
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

func TestProjectionAccountingIncludesRawFindingsAndCorrelations(t *testing.T) {
	findings := []Finding{{ID: 41, Finding: scanner.Finding{
		RuleID: "review.rule", RuleName: "Review artifact", Category: "configuration",
		TriageClass: "review", Host: "host", Share: "share", FilePath: "bundle.zip",
		ArchivePath: "bundle.zip", ArchiveMemberPath: "nested/config.xml", ObservationID: "obs-41",
		MatchedText: "æ ø å\nsecond line", Context: "English and norsk context",
	}}}
	correlations := []Correlation{{Key: "corr-1", Payload: `{"type":"same_identity_value"}`}}
	categories, audit := buildCategoriesWithAccounting("scan-raw", nil, findings, correlations)
	if audit.TotalPersistedRows != 2 || audit.PersistedFindingRows != 1 || audit.PersistedCorrelationRows != 1 || audit.UnaccountedRows != 0 {
		t.Fatalf("raw projection accounting mismatch: %#v", audit)
	}
	if audit.PresentedRows != 2 || len(categories) != 2 {
		t.Fatalf("raw rows were not independently presented: %#v", audit)
	}
	var rendered discovery
	for _, group := range categories {
		for _, item := range group.Discoveries {
			if item.FindingRef == "finding:41" {
				rendered = item
			}
		}
	}
	if rendered.Finding != nil || rendered.FindingRef != "finding:41" {
		t.Fatalf("raw finding was retained in the projection instead of its stable reference: %#v", rendered)
	}
}

func TestFindingProjectionRetainsStableReferenceWithoutFullPayload(t *testing.T) {
	findings := []Finding{{ID: 41, Finding: scanner.Finding{
		RuleID: "review.rule", RuleName: "Review artifact", Category: "configuration", FilePath: "bundle.zip",
		MatchedText: "evidence", ObservationID: "obs-41",
	}}}
	categories, _ := buildCategoriesWithAccounting("scan-runtime", nil, findings, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 {
		t.Fatalf("unexpected finding projection: %#v", categories)
	}
	discovery := categories[0].Discoveries[0]
	if discovery.Finding != nil || discovery.FindingRef != "finding:41" || len(discovery.PersistedRefs) != 1 {
		t.Fatalf("finding projection retained payload instead of stable reference: %#v", discovery)
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

func TestCredentialProjectionUsesPersistedRowIdentityDuringRelationshipExpansion(t *testing.T) {
	credentials := []Credential{
		{ID: 101, CredentialKey: "same-key", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "alice", Value: "shared", Path: "a.ini", Verification: credentialanalysis.Confirmed}},
		{ID: 102, CredentialKey: "same-key", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "alice", Value: "shared", Path: "b.ini", Verification: credentialanalysis.Confirmed}},
	}
	categories, audit := buildCategoriesWithAccounting("scan-row-identity", credentials, nil, nil)
	if audit.UnaccountedRows != 0 || audit.TotalPersistedRows != 2 || audit.PresentedRows != 1 || audit.GroupedRows != 1 {
		t.Fatalf("persisted row identity was not reconciled: %#v", audit)
	}
	if got := len(categories[0].Discoveries[0].PersistedRefs); got != 2 {
		t.Fatalf("logical group retained %d persisted rows, want 2", got)
	}
	if got := categories[0].Discoveries[0].PersistedRefs; got[0] != "credential:101" || got[1] != "credential:102" {
		t.Fatalf("unexpected persisted row refs: %#v", got)
	}
}

func TestCredentialProjectionGroupsLogicalPairsWithoutLosingRows(t *testing.T) {
	credentials := []Credential{
		accountingCredential("same-a", "password", "alice", "Shared-Pass!", "a.ini", credentialanalysis.Confirmed),
		accountingCredential("same-b", "password", "alice", "Shared-Pass!", "b.ini", credentialanalysis.Confirmed),
		accountingCredential("same-c", "password", "bob", "Shared-Pass!", "c.ini", credentialanalysis.Confirmed),
		accountingCredential("alice-other", "password", "alice", "Other-Pass!", "d.ini", credentialanalysis.Confirmed),
	}
	categories, audit := buildCategoriesWithAccounting("scan-dedup", credentials, nil, nil)
	if audit.UnaccountedRows != 0 || audit.PresentedRows != 3 || audit.GroupedRows != 1 {
		t.Fatalf("dedup accounting mismatch: %#v", audit)
	}
	var logical int
	var sourceCount int
	for _, group := range categories {
		for _, discovery := range group.Discoveries {
			if discovery.Identity == "alice" {
				logical++
				if discovery.Value == "Shared-Pass!" {
					sourceCount = len(discovery.PersistedRefs)
				}
			}
		}
	}
	if logical != 2 || sourceCount != 2 {
		t.Fatalf("expected two alice discoveries and two grouped source rows, logical=%d sources=%d", logical, sourceCount)
	}
}

func TestCredentialProjectionGroupsConnectionPairRowsWithPlainPair(t *testing.T) {
	credentials := []Credential{
		accountingCredential("connection", "connection_string", "", "Server=db;User ID=svc;Password=Conn-Pass!", "app.config", credentialanalysis.Confirmed),
		accountingCredential("plain", "password", "svc", "Conn-Pass!", "app.config", credentialanalysis.Confirmed),
	}
	categories, audit := buildCategoriesWithAccounting("scan-connection-dedup", credentials, nil, nil)
	if audit.UnaccountedRows != 0 || audit.GroupedRows != 1 {
		t.Fatalf("connection dedup accounting mismatch: %#v", audit)
	}
	var discoveries int
	for _, group := range categories {
		for _, discovery := range group.Discoveries {
			if discovery.Identity == "svc" && discovery.RecoveredPassword == "Conn-Pass!" {
				discoveries++
				if len(discovery.PersistedRefs) != 2 {
					t.Fatalf("connection pair refs=%d, want 2", len(discovery.PersistedRefs))
				}
			}
		}
	}
	if discoveries != 1 {
		t.Fatalf("connection pair discoveries=%d, want 1", discoveries)
	}
}

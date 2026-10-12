package credentialanalysis

import "testing"

// Every identity, path and value in this file is independently invented
// synthetic data. None of it is derived from customer, lab or live scan
// material.

// TestMaterialClassificationSeparatesSecretsFromCorrelations covers the
// actionable-vs-supporting distinction: a record is secret material only when it
// is typed as a concrete secret and holds a value.
func TestMaterialClassificationSeparatesSecretsFromCorrelations(t *testing.T) {
	t.Parallel()

	secrets := []Candidate{
		{Verification: Confirmed, CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticReal482!", Path: "configs/a.ini"},
		{Verification: Confirmed, CredentialType: "password", Value: "Summer2026.", Path: "configs/b.ini"},
		{Verification: Confirmed, CredentialType: "connection_string", Value: "Server=db.synthetic.test;Password=SyntheticDB482!;", Path: "configs/c.config"},
		{Verification: Confirmed, CredentialType: "private_key", Value: "synthetic key material", Path: "keys/id_ed25519"},
		{Verification: Confirmed, CredentialType: "nt_hash", Value: "00112233445566778899aabbccddeeff", Path: "Windows/NTDS/ntds.dit"},
		{Verification: Confirmed, CredentialType: "token", Value: "SyntheticToken482!", Path: "configs/d.json"},
	}
	correlations := []Candidate{
		{Verification: Confirmed, CredentialType: "application/deployment credential indicator", Identity: "synthetic-service", Value: "synthetic record", Path: "deploy/a.ini"},
		{Verification: Confirmed, CredentialType: "credential_store_presence", Material: MaterialCorrelation, Path: "Users/synthetic/AppData/Local/Synthetic/store"},
		{Verification: Confirmed, CredentialType: "password", Material: MaterialCorrelation, Path: "configs/identity-only.ini"},
	}

	report := Analyze(append(append([]Candidate{}, secrets...), correlations...))
	if len(report.Confirmed) != len(secrets)+len(correlations) {
		t.Fatalf("confirmed records = %d, want %d", len(report.Confirmed), len(secrets)+len(correlations))
	}
	secretRecords, correlationRecords := 0, 0
	for _, record := range report.Confirmed {
		switch record.Material {
		case MaterialSecret:
			secretRecords++
			if !IsSecretMaterialType(record.CredentialType) || !record.ValuePresent {
				t.Fatalf("secret record is not backed by a value and a secret type: %#v", record)
			}
		case MaterialCorrelation:
			correlationRecords++
		default:
			t.Fatalf("record has no material classification: %#v", record)
		}
	}
	if secretRecords != len(secrets) || correlationRecords != len(correlations) {
		t.Fatalf("material split = %d secret / %d correlation, want %d / %d", secretRecords, correlationRecords, len(secrets), len(correlations))
	}

	// A value-less record that is not explicitly correlation evidence stays
	// dropped: the ledger never invents a credential from an empty value.
	dropped := Analyze([]Candidate{{Verification: Confirmed, CredentialType: "credential_store_presence", Path: "Users/synthetic/store"}})
	if len(dropped.Confirmed) != 0 {
		t.Fatalf("value-less unmarked record entered the ledger: %#v", dropped.Confirmed)
	}
}

// TestCorrelationRecordsMayCarryNoValue proves the ledger can represent an
// identity- or artifact-only record without inventing a secret for it.
func TestCorrelationRecordsMayCarryNoValue(t *testing.T) {
	t.Parallel()

	report := Analyze([]Candidate{{
		Verification:   Confirmed,
		CredentialType: "application/deployment credential indicator",
		Identity:       "synthetic-service",
		Material:       MaterialCorrelation,
		Host:           "synthetic-host.test",
		Share:          "SyntheticShare",
		Path:           "deploy/synthetic-locations.ini",
	}})
	if len(report.Confirmed) != 1 {
		t.Fatalf("identity-only correlation was dropped: %#v", report)
	}
	record := report.Confirmed[0]
	if record.Material != MaterialCorrelation || record.ValuePresent {
		t.Fatalf("record was not kept as correlation evidence: %#v", record)
	}
	if record.Identity != "synthetic-service" {
		t.Fatalf("identity was lost: %#v", record)
	}
}

// TestActionableSecretsAreNeverClassifiedAsCorrelation is the false-negative
// guard for the material split.
func TestActionableSecretsAreNeverClassifiedAsCorrelation(t *testing.T) {
	t.Parallel()

	actionable := []Candidate{
		{Verification: Confirmed, CredentialType: "password", Identity: "synthetic-user", Value: "SyntheticReal482!", Path: "configs/pair.ini"},
		{Verification: Confirmed, CredentialType: "password", Identity: "Administrator", Value: "Summer2026.", Path: "configs/admin.ini"},
		{Verification: Confirmed, CredentialType: "connection_string", Value: "Server=db.synthetic.test;User ID=svc_synthetic;Password=SyntheticDB482!;", Path: "configs/db.config"},
		{Verification: Confirmed, CredentialType: "private_key", Value: "synthetic key material", Path: "keys/id_ed25519"},
		{Verification: Confirmed, CredentialType: "nt_hash", Value: "00112233445566778899aabbccddeeff", Path: "Windows/NTDS/ntds.dit"},
		{Verification: Confirmed, CredentialType: "password", Identity: "archive-user", Value: "SyntheticArchive482!", Path: "packages/configs.zip!app/settings.ini", Container: "packages/configs.zip"},
	}
	for _, candidate := range actionable {
		if classifyMaterial(candidate) != MaterialSecret {
			t.Fatalf("real secret %q (%s) was classified as supporting correlation", candidate.Value, candidate.CredentialType)
		}
	}
}

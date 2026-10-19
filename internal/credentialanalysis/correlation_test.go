package credentialanalysis

import "testing"

func TestCorrelateRequiresIdentityTypeAndDistinctOrigins(t *testing.T) {
	t.Parallel()
	candidates := []Candidate{
		{CredentialType: "password", Identity: "SYNTHETIC\\svc", Value: "Synthetic-Password-482!", Host: "host", Share: "share", Path: "one.ini", Verification: Confirmed},
		{CredentialType: "password", Identity: "synthetic\\svc", Value: "Synthetic-Password-482!", Host: "host", Share: "share", Path: "two.ini", Verification: Confirmed},
		{CredentialType: "password", Identity: "other-user", Value: "Synthetic-Password-482!", Host: "host", Share: "share", Path: "other.ini", Verification: Confirmed},
		{CredentialType: "nt_hash", Identity: "synthetic\\svc", Value: "0123456789abcdef0123456789abcdef", Host: "host", Share: "share", Path: "hash.txt", Verification: Confirmed},
		{CredentialType: "password", Identity: "synthetic\\svc", Value: "********", Host: "host", Share: "share", Path: "masked.txt", Verification: Confirmed},
	}
	correlations := Correlate(candidates)
	if len(correlations) != 1 {
		t.Fatalf("got %d correlations, want one: %#v", len(correlations), correlations)
	}
	correlation := correlations[0]
	if correlation.Type != "same_identity_value" || correlation.Confidence != "high" || correlation.ObservationCount != 2 {
		t.Fatalf("unexpected correlation: %#v", correlation)
	}
	if len(correlation.Sources) != 2 || correlation.Sources[0].Path != "one.ini" || correlation.Sources[1].Path != "two.ini" {
		t.Fatalf("unexpected source provenance: %#v", correlation.Sources)
	}
}

func TestCorrelateDifferentValuesRemainMediumAndStable(t *testing.T) {
	t.Parallel()
	left := Candidate{CredentialType: "password", Identity: "svc", Value: "first-value", Host: "host", Share: "share", Path: "a.ini", Verification: Confirmed}
	right := Candidate{CredentialType: "password", Identity: "svc", Value: "second-value", Host: "host", Share: "share", Path: "b.ini", Verification: Confirmed}
	first := Correlate([]Candidate{left, right})
	second := Correlate([]Candidate{right, left})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one correlation: %#v %#v", first, second)
	}
	if first[0].Key != second[0].Key || first[0].Confidence != "medium" || first[0].Type != "same_identity_type" {
		t.Fatalf("correlation is not deterministic: %#v %#v", first, second)
	}
}

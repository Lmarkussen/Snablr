package credentialanalysis

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeClassifiesAndDeduplicatesWithoutSerializingValues(t *testing.T) {
	candidates := []Candidate{
		{Verification: Confirmed, CredentialType: "nt_hash", Identity: " Administrator ", Domain: "LAB", Value: "0123456789abcdef0123456789abcdef", ValidationBasis: "cryptographic_ntds_recovery", Evidence: []Evidence{{RuleID: "ntds"}}},
		{Verification: Confirmed, CredentialType: "nt_hash", Identity: "Administrator", Domain: "lab", Value: "0123456789abcdef0123456789abcdef", Evidence: []Evidence{{RuleID: "structured"}}},
		{Verification: Review, CredentialType: "password", Value: "possible-secret", ReviewReasons: []string{"identity association ambiguous"}},
		{Verification: Review, CredentialType: "token", Identity: "svc", Value: "possible-token", ReviewReasons: []string{"semantic validation unavailable"}},
		{CredentialType: "password", Value: ""},
	}
	report := Analyze(candidates)
	if report.CandidatesAnalyzed != 4 || len(report.Confirmed) != 1 || len(report.Review) != 2 || report.DuplicatesMerged != 1 {
		t.Fatalf("unexpected report: analyzed=%d confirmed=%d review=%d merged=%d", report.CandidatesAnalyzed, len(report.Confirmed), len(report.Review), report.DuplicatesMerged)
	}
	if !report.Confirmed[0].ValuePresent || len(report.Confirmed[0].Evidence) != 2 {
		t.Fatalf("expected safe presence and merged provenance: %#v", report.Confirmed[0])
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "0123456789abcdef0123456789abcdef") || strings.Contains(string(encoded), "possible-secret") {
		t.Fatalf("sensitive candidate value serialized: %s", encoded)
	}
}

func TestAnalyzePreservesDistinctValuesAndNormalizesUnknownVerification(t *testing.T) {
	report := Analyze([]Candidate{
		{Verification: "", CredentialType: "password", Identity: "user", Value: "one"},
		{Verification: "review", CredentialType: "password", Identity: "user", Value: "two"},
	})
	if len(report.Review) != 2 || report.Review[0].ValuePresent != true || report.Review[1].ValuePresent != true {
		t.Fatalf("distinct review candidates were not retained: %#v", report.Review)
	}
}

func TestAnalyzePromotesReviewWhenConfirmedEvidenceArrives(t *testing.T) {
	report := Analyze([]Candidate{
		{Verification: Review, CredentialType: "password", Identity: "svc", Value: "value", ReviewReasons: []string{"ambiguous"}},
		{Verification: Confirmed, CredentialType: "password", Identity: "svc", Value: "value", ValidationBasis: "structured_config_pair"},
	})
	if len(report.Confirmed) != 1 || len(report.Review) != 0 || report.Confirmed[0].ValidationBasis != "structured_config_pair" {
		t.Fatalf("review candidate was not promoted: %#v", report)
	}
}

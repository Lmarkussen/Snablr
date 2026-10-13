package credentialanalysis

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeClassifiesAndDeduplicatesWithoutSerializingValues(t *testing.T) {
	candidates := []Candidate{
		{Verification: Confirmed, CredentialType: "nt_hash", Identity: " synthetic-admin ", Domain: "SYNTHETIC", Value: "00112233445566778899aabbccddeeff", ValidationBasis: "cryptographic_ntds_recovery", Evidence: []Evidence{{RuleID: "ntds"}}},
		{Verification: Confirmed, CredentialType: "nt_hash", Identity: "synthetic-admin", Domain: "synthetic", Value: "00112233445566778899aabbccddeeff", Evidence: []Evidence{{RuleID: "structured"}}},
		{Verification: Review, CredentialType: "password", Value: "SyntheticPossible482!", ReviewReasons: []string{"identity association ambiguous"}},
		{Verification: Review, CredentialType: "token", Identity: "synthetic-service", Value: "SyntheticToken482!", ReviewReasons: []string{"semantic validation unavailable"}},
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
	if strings.Contains(string(encoded), "00112233445566778899aabbccddeeff") || strings.Contains(string(encoded), "SyntheticPossible482!") {
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

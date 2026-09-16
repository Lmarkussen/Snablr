package output

import (
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// TestPostScanNorwegianStructuredPairIsConfirmed exercises the shared
// credential-key semantics inside the post-scan classifier (a second consumer
// of the same alias layer the harvester uses).
func TestPostScanNorwegianStructuredPairIsConfirmed(t *testing.T) {
	finding := scanner.Finding{
		FilePath:    "Users/Alice/Desktop/notater.txt",
		MatchedText: "Domene=OKONOMI\nBrukernavn=svc_backup\nPassord=Post-Scan-Hemmelighet-123!",
	}
	report := analyzeCandidates([]scanner.Finding{finding}, nil)

	found := false
	for _, candidate := range report.Confirmed {
		if candidate.CredentialType != "password" || candidate.Identity != "svc_backup" {
			continue
		}
		found = true
		if candidate.ValuePresent != true {
			t.Fatalf("confirmed Norwegian candidate did not report a value present")
		}
	}
	if !found {
		t.Fatalf("Norwegian post-scan pair was not confirmed: %#v", report)
	}
	for _, candidate := range report.Confirmed {
		if candidate.Verification != credentialanalysis.Confirmed {
			t.Fatalf("confirmed section contained non-confirmed candidate: %#v", candidate)
		}
	}
}

// TestPostScanNorwegianMetadataProducesNoCandidate verifies the negative case
// in the post-scan path: policy metadata never becomes a credential.
func TestPostScanNorwegianMetadataProducesNoCandidate(t *testing.T) {
	finding := scanner.Finding{
		FilePath:    "policy/passord-policy.ini",
		MatchedText: "PassordPolicy=Kompleksitet\nPassordLengde=12\nPassordKrav=StoreOgSmaa",
	}
	report := analyzeCandidates([]scanner.Finding{finding}, nil)
	if len(report.Confirmed) != 0 || len(report.Review) != 0 {
		t.Fatalf("Norwegian policy metadata produced credential candidates: %#v", report)
	}
}

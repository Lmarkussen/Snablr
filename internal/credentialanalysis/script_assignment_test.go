package credentialanalysis

import "testing"

func TestServiceScriptAssignmentsAreHarvested(t *testing.T) {
	t.Parallel()

	tests := []string{
		`$SvcPass = "Synthetic-Service-123!"`,
		`export RUN_PASSWORD=Synthetic-Run-456!`,
		`SvcPassword=Synthetic-Service-789!`,
		`ServicePass=Synthetic-Service-101!`,
	}
	for _, content := range tests {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "deploy.ps1"})
		if len(candidates) == 0 {
			t.Fatalf("expected service password candidate for %q, got none", content)
		}
		found := false
		for _, candidate := range candidates {
			if candidate.CredentialType == "password" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected password candidate for %q, got %#v", content, candidates)
		}
	}
}

func TestServiceScriptAssignmentFalsePositiveControls(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		`Bypass=Synthetic-123!`,
		`Compass=Synthetic-123!`,
		`Trespass=Synthetic-123!`,
		`PassCount=4`,
		`ServicePassEnabled=false`,
		`PasswordPolicy=Strong`,
	} {
		if candidates := Harvest(HarvestInput{Content: []byte(content), Path: "settings.ini"}); len(candidates) != 0 {
			t.Fatalf("expected no credential candidate for %q, got %#v", content, candidates)
		}
	}
}

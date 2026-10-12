package credentialanalysis

import "testing"

// Every value and path in this file is independently invented synthetic data.
// None of it is derived from customer, lab or live scan material.

func analyzeHarvested(path, content string) Report {
	return Analyze(Harvest(HarvestInput{Content: []byte(content), Path: path}))
}

// TestWeakReviewCandidatesAreSuppressedFromTheLedger is the synthetic regression
// matrix for PROBLEM A: a credential-like key name with an opaque, non-secret
// value and no identity must not enter the operator credential ledger.
func TestWeakReviewCandidatesAreSuppressedFromTheLedger(t *testing.T) {
	t.Parallel()

	weak := []struct {
		name    string
		path    string
		content string
	}{
		{
			name:    "arbitrary json data map",
			path:    "data/synthetic-map.json",
			content: `{"cacheToken":"a1","sessionSecret":"b2","renderToken":"c3"}`,
		},
		{
			name:    "arbitrary line data",
			path:    "data/synthetic-lines.dat",
			content: "token=a1\nsecret=b2\nauth_token=c3\n",
		},
		{
			name:    "arbitrary container data",
			path:    "data/synthetic-blob.pak",
			content: "session_token=d4\napi_key=e5\n",
		},
	}

	for _, test := range weak {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := analyzeHarvested(test.path, test.content)
			if countReportCandidates(report) != 0 {
				t.Fatalf("weak candidate entered the ledger: confirmed=%d review=%d", len(report.Confirmed), len(report.Review))
			}
			if report.SuppressedWeakReview == 0 {
				t.Fatalf("weak candidate was not counted as suppressed: %#v", report)
			}
		})
	}
}

// TestStrongCredentialsWithoutIdentitySurviveTheGate is the false-negative
// safety net: explicit assignments and strongly shaped secrets must be retained
// even when no identity is known.
func TestStrongCredentialsWithoutIdentitySurviveTheGate(t *testing.T) {
	t.Parallel()

	strong := []struct {
		name    string
		path    string
		content string
	}{
		{"explicit password", "config/synthetic-explicit.env", "Password=SyntheticStrong482!\n"},
		{"admin password", "config/synthetic-admin.env", "AdminPassword=Summer2026.\n"},
		{"short dictionary-like password", "config/synthetic-short.env", "Pwd=WeakButReal\n"},
		{"powershell service password", "scripts/synthetic-deploy.ps1", "$SvcPass = \"SyntheticService482!\"\n"},
		{"shell run password", "scripts/synthetic-run.sh", "export RUN_PASSWORD=SyntheticRun482!\n"},
		{"username and password pair", "config/synthetic-pair.ini", "[SyntheticApp]\nUsername=synthetic-user\nPassword=SyntheticPair482!\n"},
		{"jwt shaped token", "config/synthetic-token.json", `{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMCJ9.SyntheticSignatureSegment000000000000"}`},
	}

	for _, test := range strong {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := analyzeHarvested(test.path, test.content)
			if countReportCandidates(report) == 0 {
				t.Fatalf("strong credential was suppressed by the review gate: %#v", report)
			}
			if report.SuppressedWeakReview != 0 {
				t.Fatalf("strong credential was counted as weak review noise: %#v", report)
			}
		})
	}
}

// TestRecoveredCredentialTypesAreNeverGated confirms the gate is scoped to
// generic review material: recovered and composite credential types always keep
// their place in the ledger.
func TestRecoveredCredentialTypesAreNeverGated(t *testing.T) {
	t.Parallel()

	report := Analyze([]Candidate{
		{Verification: Review, CredentialType: "connection_string", Value: "Server=db.synthetic.test;User ID=svc_synthetic;Password=SyntheticDB482!;", Path: "config/synthetic-db.config"},
		{Verification: Review, CredentialType: "private_key", Value: "PRIVATE KEY", Path: "keys/synthetic.key"},
		{Verification: Review, CredentialType: "nt_hash", Value: "00112233445566778899aabbccddeeff", Path: "Windows/NTDS/ntds.dit"},
	})
	if report.SuppressedWeakReview != 0 {
		t.Fatalf("recovered credential types were gated: %#v", report)
	}
	if len(report.Review) != 3 {
		t.Fatalf("review records = %d, want 3: %#v", len(report.Review), report.Review)
	}
}

// TestReviewGateKeepsIdentityBearingSecrets proves a structured key/value pair
// with an account identity still reaches review even when the value has no
// token shape.
func TestReviewGateKeepsIdentityBearingSecrets(t *testing.T) {
	t.Parallel()

	report := Analyze([]Candidate{{
		Verification:   Review,
		CredentialType: "secret",
		Identity:       "synthetic-user",
		Value:          "opaque-synthetic-value",
		Path:           "config/synthetic-identity.json",
	}})
	if len(report.Review) != 1 {
		t.Fatalf("identity-bearing secret was suppressed: %#v", report)
	}
}

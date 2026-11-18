package seed

import (
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func pairManifest() Manifest {
	return Manifest{Entries: []SeedManifestEntry{
		{
			Host: "192.0.2.10", Share: "SyntheticShare", Path: "Configs/app.config", Category: "credentials",
			IntendedAs: "credential", ExpectedPairs: 2, FixtureID: "fx-app",
			ExpectedPairsDetail: []ExpectedCredentialPair{
				{ID: "p1", Username: "svc_synthetic_a", Password: "SYNTHETIC_PASS_A"},
				{ID: "p2", Username: "svc_synthetic_b", Password: "SYNTHETIC_PASS_B"},
			},
		},
		{
			Host: "192.0.2.10", Share: "SyntheticShare", Path: "Archives/bundle.zip!inner/settings.ini", Category: "credentials",
			IntendedAs: "credential", ExpectedPairs: 1,
			ExpectedUsername: "svc_synthetic_zip", ExpectedPassword: "SYNTHETIC_PASS_ZIP",
		},
		{
			Host: "192.0.2.10", Share: "SyntheticShare", Path: "Noise/readme.txt", Category: "noise", IntendedAs: "filler",
		},
	}}
}

func passwordCandidate(host, path, identity, value string) credentialanalysis.Candidate {
	return credentialanalysis.Candidate{
		Verification: credentialanalysis.Confirmed, CredentialType: "password",
		Identity: identity, Value: value, Host: host, Share: "SyntheticShare", Path: path,
	}
}

func TestVerifyCredentialPairsMatchesDetailAndSinglePairs(t *testing.T) {
	credentials := []credentialanalysis.Candidate{
		passwordCandidate("192.0.2.10", "Configs/app.config", "svc_synthetic_a", "SYNTHETIC_PASS_A"),
		// Wrong password for the second detail pair: must not count.
		passwordCandidate("192.0.2.10", "Configs/app.config", "svc_synthetic_b", "SYNTHETIC_WRONG"),
		// Archive member recovered with its member path.
		passwordCandidate("192.0.2.10", "Archives/bundle.zip!inner/settings.ini", "svc_synthetic_zip", "SYNTHETIC_PASS_ZIP"),
		// Correct pair but from the wrong file: must not count.
		passwordCandidate("192.0.2.10", "Other/app.config", "svc_synthetic_b", "SYNTHETIC_PASS_B"),
	}
	report := VerifyCredentialPairs(pairManifest(), credentials, true)
	if report.EntriesWithPairs != 2 || report.ExpectedPairs != 3 {
		t.Fatalf("entries=%d expected=%d, want 2/3", report.EntriesWithPairs, report.ExpectedPairs)
	}
	if report.MatchedPairs != 2 {
		t.Fatalf("matched=%d, want 2", report.MatchedPairs)
	}
	if len(report.Missing) != 1 || report.Missing[0].Username != "svc_synthetic_b" {
		t.Fatalf("missing=%+v, want svc_synthetic_b", report.Missing)
	}
}

func TestVerifyCredentialPairsHostFallbackMatchesByShareAndPath(t *testing.T) {
	credentials := []credentialanalysis.Candidate{
		passwordCandidate("fileserver.example.test", "Configs/app.config", "svc_synthetic_a", "SYNTHETIC_PASS_A"),
	}
	if strict := VerifyCredentialPairs(pairManifest(), credentials, true); strict.MatchedPairs != 0 {
		t.Fatalf("strict host matching matched %d pairs across different host names", strict.MatchedPairs)
	}
	if fallback := VerifyCredentialPairs(pairManifest(), credentials, false); fallback.MatchedPairs != 1 {
		t.Fatalf("host fallback matched %d pairs, want 1", fallback.MatchedPairs)
	}
}

func TestVerifyFindingsFallsBackWhenManifestAndScanHostsDiffer(t *testing.T) {
	manifest := pairManifest()
	findings := []scanner.Finding{{RuleID: "synthetic.rule", Host: "fileserver.example.test", Share: "SyntheticShare", FilePath: "Configs/app.config", Category: "credentials"}}

	report := verifyFindings("manifest.json", findings, manifest)
	if !report.HostFallback {
		t.Fatal("expected host fallback when no manifest host matches a scanned host")
	}
	if report.FoundItems != 1 {
		t.Fatalf("found=%d, want 1 with share+path fallback", report.FoundItems)
	}
	if manifest.Entries[0].Host != "192.0.2.10" {
		t.Fatal("host fallback mutated the caller's manifest")
	}

	findings[0].Host = "192.0.2.10"
	if strict := verifyFindings("manifest.json", findings, manifest); strict.HostFallback {
		t.Fatal("host fallback used although manifest and scan hosts match")
	}
}

func TestCountNotWrittenEntries(t *testing.T) {
	manifest := Manifest{Entries: []SeedManifestEntry{{Status: "dry-run"}, {Status: "written"}, {Status: "unchanged"}, {Status: "DRY-RUN"}}}
	if got := countNotWrittenEntries(manifest); got != 2 {
		t.Fatalf("not written=%d, want 2", got)
	}
}

// Actionable findings on negative controls are false positives; findings on
// review material (unpaired or protected credentials) are the desired outcome
// and must not be counted against precision.
func TestVerifyFindingsSeparatesFalsePositivesFromReviewMaterial(t *testing.T) {
	manifest := Manifest{Entries: []SeedManifestEntry{
		{Host: "192.0.2.10", Share: "SyntheticShare", Path: "neg/placeholder.txt", ExpectedClass: "negative", NegativeReason: "placeholder or masked value"},
		{Host: "192.0.2.10", Share: "SyntheticShare", Path: "neg/policy.txt", ExpectedClass: "negative", NegativeReason: "password policy documentation"},
		{Host: "192.0.2.10", Share: "SyntheticShare", Path: "review/orphan.txt", ExpectedClass: "review", NegativeReason: "password-only reference"},
		{Host: "192.0.2.10", Share: "SyntheticShare", Path: "review/silent.txt", ExpectedClass: "review", NegativeReason: "opaque/encrypted material"},
	}}
	findings := []scanner.Finding{
		{RuleID: "synthetic.actionable", Host: "192.0.2.10", Share: "SyntheticShare", FilePath: "neg/placeholder.txt", Actionable: true},
		{RuleID: "synthetic.weak", Host: "192.0.2.10", Share: "SyntheticShare", FilePath: "neg/policy.txt", Actionable: false},
		{RuleID: "synthetic.review", Host: "192.0.2.10", Share: "SyntheticShare", FilePath: "review/orphan.txt", Actionable: true},
	}
	report := verifyFindings("manifest.json", findings, manifest)
	if report.NegativeControls != 2 || len(report.NegativeActionable) != 1 || report.NegativeActionable[0].Path != "neg/placeholder.txt" {
		t.Fatalf("negative controls=%d false positives=%+v", report.NegativeControls, report.NegativeActionable)
	}
	if report.ReviewMaterial != 2 || report.ReviewSurfaced != 1 {
		t.Fatalf("review material=%d surfaced=%d, want 2/1", report.ReviewMaterial, report.ReviewSurfaced)
	}
}

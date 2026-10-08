package output

import (
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// 12/14. A path that merely indicates a credential store exists is inventory
// and attack-surface evidence. It must never be projected into the Credential &
// Secret Material analysis, even when a correlation promoted it to a primary
// exposure finding. All values are synthetic.
func TestNoisePathOnlyStoresAreNotCredentialMaterial(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{
		{RuleID: "wincredinspect.path.credentials", Category: "windows-credentials", Confidence: "high", ConfidenceScore: 60, FilePath: `Users\synthetic\AppData\Roaming\Microsoft\Credentials\A1B2C3`},
		{RuleID: "wincredinspect.path.vault", Category: "windows-credentials", Confidence: "high", FilePath: `Users\synthetic\AppData\Local\Microsoft\Vault\D4E5F6`},
		{RuleID: "wincredinspect.path.protect", Category: "windows-credentials", Confidence: "medium", FilePath: `Users\synthetic\AppData\Roaming\Microsoft\Protect\S-1-5-21-0`},
		{RuleID: "browsercredinspect.chromium.login_data", Category: "browser-credentials", Confidence: "high", FilePath: `Users\synthetic\AppData\Local\Google\Chrome\User Data\Default\Login Data`},
		{RuleID: "browsercredinspect.chromium.cookies", Category: "browser-credentials", Confidence: "low", FilePath: `Users\synthetic\AppData\Local\Google\Chrome\User Data\Default\Cookies`},
		{RuleID: "correlation.windows.dpapi_credential_store", Category: "windows-credentials", Confidence: "high", ConfidenceScore: 84, Actionable: true},
		{RuleID: "correlation.browser.profile_credential_store", Category: "browser-credentials", Confidence: "high", ConfidenceScore: 78, Actionable: true},
	}

	if candidates := credentialCandidatesFromFindings(findings); len(candidates) != 0 {
		t.Fatalf("path-only credential stores produced credential candidates: %#v", candidates)
	}
	report := analyzeCandidates(findings, nil)
	if len(report.Confirmed) != 0 || len(report.Review) != 0 {
		t.Fatalf("path-only credential stores entered credential material: %#v", report)
	}
}

// 13/15. A real recovered secret (for example a structured browser credential
// record) is still credential material.
func TestNoiseRecoveredSecretIsCredentialMaterial(t *testing.T) {
	t.Parallel()
	candidates := []credentialanalysis.Candidate{
		{Verification: credentialanalysis.Confirmed, CredentialType: "password", Identity: "synthetic-user", Value: "Synthetic-Browser-447!", Path: "synthetic/browser-record.json"},
	}
	report := analyzeCandidates(nil, candidates)
	if len(report.Confirmed) != 1 {
		t.Fatalf("recovered secret was not treated as credential material: %#v", report)
	}
	if report.Confirmed[0].ValuePresent != true {
		t.Fatalf("recovered secret lost its value-present flag: %#v", report.Confirmed[0])
	}
}

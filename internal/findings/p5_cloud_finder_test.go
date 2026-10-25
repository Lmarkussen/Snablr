package findings

import (
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func TestApplicationCloudFindingsUseProviderSubcategories(t *testing.T) {
	findings := []Finding{
		{Finding: scanner.Finding{RuleID: "cloudinspect.aws.application_bundle", RuleName: "AWS bundle", Category: "cloud", MatchedText: "aws-evidence"}},
		{Finding: scanner.Finding{RuleID: "cloudinspect.azure.client_secret_config", RuleName: "Azure secret", Category: "cloud", MatchedText: "azure-evidence"}},
		{Finding: scanner.Finding{RuleID: "cloudinspect.gcp.service_account", RuleName: "GCP service account", Category: "cloud", MatchedText: "gcp-evidence"}},
		{Finding: scanner.Finding{RuleID: "cloudinspect.gcp.external_account", RuleName: "GCP external account", Category: "cloud", MatchedText: "reference-evidence"}},
	}

	categories := buildCategories(nil, findings, nil)
	if len(categories) != 1 || categories[0].Name != "Application & Cloud Secrets" {
		t.Fatalf("unexpected Finder categories: %#v", categories)
	}
	if got := len(categories[0].Discoveries); got != len(findings) {
		t.Fatalf("cloud observations were dropped or duplicated: got %d want %d", got, len(findings))
	}
	want := []string{
		"AWS Credentials",
		"Azure / Entra Credentials",
		"Google Cloud Credentials",
		"Secret References & Configuration Artifacts",
	}
	for index, discovery := range categories[0].Discoveries {
		if discovery.Subcategory != want[index] {
			t.Fatalf("cloud finding %d subcategory = %q, want %q", index, discovery.Subcategory, want[index])
		}
		if discovery.Finding != nil || discovery.FindingRef != discovery.PersistedRefs[0] {
			t.Fatalf("cloud finding %d did not retain its stable evidence reference: %#v", index, discovery)
		}
	}
}

func TestApplicationCloudSubcategoryDoesNotChangeCredentialProjection(t *testing.T) {
	category, subcategory := classifyCandidate(credentialanalysis.Candidate{CredentialType: "api_key", Value: "synthetic-api-secret", Verification: credentialanalysis.Confirmed})
	if category != "Application & Cloud Secrets" || subcategory == "AWS Credentials" {
		t.Fatalf("generic credential was assigned provider-specific cloud ownership: %q / %q", category, subcategory)
	}
}

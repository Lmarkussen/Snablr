package credentialanalysis

import "testing"

// These tests are the synthetic false-positive / regression matrix for
// structured credential extraction. Every value is independently invented;
// none of it is derived from customer, lab or live scan material.

func harvestForNoiseTest(path, content string) []Candidate {
	return Harvest(HarvestInput{Content: []byte(content), Path: path})
}

func hasValueWithType(candidates []Candidate, value, credentialType string) bool {
	for _, candidate := range candidates {
		if candidate.Value == value && candidate.CredentialType == credentialType {
			return true
		}
	}
	return false
}

// 1. Generic XML metadata must not become a token merely because an element
// named Token/ApiKey exists.
func TestNoiseGenericXMLMetadataIsNotAToken(t *testing.T) {
	content := `<?xml version="1.0"?>
<SyntheticSettings>
  <Token>c4d3e2f1-a0b1-4c2d-8e3f-102030405060</Token>
  <AccessToken>session-0001</AccessToken>
  <ApiKey>synthetic-field-name</ApiKey>
  <LastUpdated>2026-01-01T00:00:00Z</LastUpdated>
</SyntheticSettings>`
	for _, candidate := range harvestForNoiseTest("settings/synthetic.xml", content) {
		if IsTokenSecretType(candidate.CredentialType) {
			t.Fatalf("generic XML metadata produced a token candidate: %#v", candidate)
		}
	}
}

// 2. A genuinely token-shaped XML value is still recovered.
func TestNoiseRealXMLTokenIsRetained(t *testing.T) {
	content := `<SyntheticSettings>
  <Token>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwIn0.SyntheticSignatureSegment0000000000000000</Token>
</SyntheticSettings>`
	got := harvestForNoiseTest("settings/synthetic.xml", content)
	if len(got) == 0 || !IsTokenSecretType(got[0].CredentialType) {
		t.Fatalf("token-shaped XML value was not retained: %#v", got)
	}
}

// 2b. A recognised API-key prefix is enough token evidence.
func TestNoiseXMLApiKeyPrefixIsRetained(t *testing.T) {
	content := `<SyntheticSettings>
  <ApiKey>AKIAIOSFODNN7SYNTHETIC</ApiKey>
</SyntheticSettings>`
	got := harvestForNoiseTest("settings/synthetic.xml", content)
	if !hasValueWithType(got, "AKIAIOSFODNN7SYNTHETIC", "api_key") {
		t.Fatalf("API-key-shaped XML value was not retained: %#v", got)
	}
}

// 3. A localization / UI resource bundle is prose, not credential data.
func TestNoiseLocalizationResourceIsRejected(t *testing.T) {
	content := `{
  "login.title": "Sign in to the synthetic portal",
  "login.error.invalidPassword": "The password you entered is incorrect",
  "login.error.invalidUsername": "The user name is not recognised",
  "_login.error.invalidPassword.comment": "Shown when the supplied password does not match",
  "common.ok": "OK",
  "common.cancel": "Cancel"
}`
	if got := harvestForNoiseTest("resources/locales/synthetic-locale.json", content); len(got) != 0 {
		t.Fatalf("localization resource produced credential candidates: %#v", got)
	}
}

// 4. A structured credential object is still recovered.
func TestNoiseStructuredJsonCredentialIsRetained(t *testing.T) {
	content := `{"username":"synthetic-user","password":"Synthetic-Json-934!"}`
	got := harvestForNoiseTest("config/synthetic.json", content)
	if !hasCandidate(got, Confirmed, "Synthetic-Json-934!") {
		t.Fatalf("structured JSON credential was not confirmed: %#v", got)
	}
}

// 5. A bare dictionary / wordlist produces no credential candidate.
func TestNoiseDictionaryWordsAreRejected(t *testing.T) {
	content := "password\n12345678\ncredentials\nsynthetic\nletmein\nadmin\n"
	if got := harvestForNoiseTest("wordlists/synthetic-passwords.txt", content); len(got) != 0 {
		t.Fatalf("dictionary wordlist produced credential candidates: %#v", got)
	}
}

// 15. A real recovered secret in an explicit assignment remains credential
// material.
func TestNoiseExplicitSecretIsRetained(t *testing.T) {
	content := "SyntheticServicePassword=Synthetic-Recovered-221!\n"
	got := harvestForNoiseTest("scripts/synthetic-deploy.ps1", content)
	if !hasCandidate(got, Review, "Synthetic-Recovered-221!") {
		t.Fatalf("explicit secret assignment was not retained: %#v", got)
	}
}

// Masked and placeholder token values must never be treated as tokens.
func TestNoiseMaskedTokenValuesAreRejected(t *testing.T) {
	content := `<SyntheticSettings><Token>********</Token><ApiKey>${SYNTHETIC_TOKEN}</ApiKey></SyntheticSettings>`
	if got := harvestForNoiseTest("settings/synthetic.xml", content); len(got) != 0 {
		t.Fatalf("masked/placeholder token values produced candidates: %#v", got)
	}
}

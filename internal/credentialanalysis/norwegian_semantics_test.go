package credentialanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func norwegianFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "norwegian-credential-regression", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

// TestNorwegianPasswordSemanticAliases exercises the shared semantic
// normalization layer directly: every listed compound key must resolve to the
// password role after casing/separator/camel-case normalization.
func TestNorwegianPasswordSemanticAliases(t *testing.T) {
	positives := []string{
		"password", "passwd", "pwd", "passord",
		"Passord", "PASSORD", "adminPassord", "AdminPassord", "AdministratorPassord",
		"admin_passord", "admin-passord", "admin.passord", "DB_PASSORD", "bruker_passord",
		"BrukerPassord", "BrukerPassordet", "DomenePassord", "ServicePassord",
		"TjenestePassord", "DatabasePassord", "DBPassord", "SQLPassord",
		"BackupPassord", "KontoPassord", "LokalAdminPassord",
	}
	for _, key := range positives {
		if role := ClassifyFieldName(key); role != FieldRolePassword {
			t.Errorf("positive %q classified as %v, want password", key, role)
		}
		if !isPasswordKey(key) || !isSecretKey(key) {
			t.Errorf("positive %q was not recognized as a secret password key", key)
		}
	}
}

// TestNorwegianMetadataIsNotACredentialKey guards the critical negative case:
// password-policy metadata that merely contains "Passord" must never be
// classified as credential-bearing.
func TestNorwegianMetadataIsNotACredentialKey(t *testing.T) {
	negatives := []string{
		"PassordPolicy", "PassordPolitikk", "PassordLengde", "MinimumPassordLengde",
		"PassordKrav", "PassordPåkrevd", "PassordHistorikk", "PassordHistorikkLengde",
		"PassordUtløp", "PassordUtlopsdato", "PassordKompleksitet", "PassordRegex",
		"PassordFelt", "PassordLabel", "PassordAktivert",
		"PasswordPolicy", "PasswordLength", "PasswordHashAlgorithm",
	}
	for _, key := range negatives {
		if role := ClassifyFieldName(key); role != FieldRoleNone {
			t.Errorf("metadata %q classified as %v, want none", key, role)
		}
		if isSecretKey(key) {
			t.Errorf("metadata %q was incorrectly treated as a secret key", key)
		}
	}
}

func TestNorwegianIdentityAndDomainSemantics(t *testing.T) {
	identity := []string{"Bruker", "Brukernavn", "BrukerNavn", "Konto", "Kontonavn", "KontoNavn", "username", "user"}
	for _, key := range identity {
		if role := ClassifyFieldName(key); role != FieldRoleIdentity {
			t.Errorf("identity %q classified as %v, want identity", key, role)
		}
	}
	domain := []string{"Domene", "domain"}
	for _, key := range domain {
		if role := ClassifyFieldName(key); role != FieldRoleDomain {
			t.Errorf("domain %q classified as %v, want domain", key, role)
		}
	}
}

// TestHarvestNorwegianCredentialFormats verifies that Norwegian credentials
// surface through INI, generic key/value, JSON, YAML and XML content.
func TestHarvestNorwegianCredentialFormats(t *testing.T) {
	structured := Harvest(HarvestInput{Content: norwegianFixture(t, "structural-identity.ini"), Path: "structural-identity.ini"})
	if !hasNorwegianCandidate(structured, Confirmed, "Strukturell-Hemmelighet-123!", "svc_backup", "OKONOMI") {
		t.Fatalf("structured INI Brukernavn+Domene+Passord was not confirmed: %#v", structured)
	}
	if !hasNorwegianCandidate(structured, Confirmed, "Tjeneste-Hemmelighet-456!", "svc_tjeneste", "OKONOMI") {
		t.Fatalf("structured INI Bruker+Passord was not confirmed: %#v", structured)
	}

	generic := Harvest(HarvestInput{Content: norwegianFixture(t, "generic-pairs.txt"), Path: "generic-pairs.txt"})
	if !hasCandidate(generic, Review, "Generisk-Hemmelighet-123!") {
		t.Fatalf("generic key/value Passord was not surfaced: %#v", generic)
	}

	jsonCandidates := Harvest(HarvestInput{Content: norwegianFixture(t, "credentials.json"), Path: "credentials.json"})
	if !hasNorwegianCandidate(jsonCandidates, Confirmed, "Json-Hemmelig-123!", "svc_json", "") {
		t.Fatalf("JSON brukernavn/passord was not confirmed: %#v", jsonCandidates)
	}

	yamlCandidates := Harvest(HarvestInput{Content: norwegianFixture(t, "credentials.yaml"), Path: "credentials.yaml"})
	if !hasNorwegianCandidate(yamlCandidates, Confirmed, "YAML-Hemmelig-123!", "svc_yaml", "") {
		t.Fatalf("YAML brukernavn/passord was not confirmed: %#v", yamlCandidates)
	}

	xmlCandidates := Harvest(HarvestInput{Content: norwegianFixture(t, "config.xml"), Path: "config.xml"})
	if !hasNorwegianCandidate(xmlCandidates, Confirmed, "XML-Hemmelig-123!", "svc_xml", "") {
		t.Fatalf("XML Brukernavn/Passord was not confirmed: %#v", xmlCandidates)
	}
}

func TestHarvestNorwegianCompoundFieldsSurface(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: norwegianFixture(t, "passord-compound-fields.ini"), Path: "passord-compound-fields.ini"})
	want := []string{
		"No-Compound-Admin-001!", "No-Compound-Administrator-002!", "No-Compound-Bruker-003!",
		"No-Compound-BrukerPassordet-004!", "No-Compound-Domene-005!", "No-Compound-Service-006!",
		"No-Compound-Tjeneste-007!", "No-Compound-Database-008!", "No-Compound-DB-009!",
		"No-Compound-SQL-010!", "No-Compound-Backup-011!", "No-Compound-Konto-012!",
		"No-Compound-LokalAdmin-013!",
	}
	surfaced := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.Value != "" {
			surfaced[candidate.Value] = true
		}
	}
	for _, value := range want {
		if !surfaced[value] {
			t.Errorf("compound Norwegian credential %q was not surfaced", value)
		}
		if candidate := candidateForValue(candidates, value); candidate != nil && candidate.CredentialType != "password" {
			t.Errorf("Norwegian credential %q had non-password semantic type %q", value, candidate.CredentialType)
		}
	}
}

func TestHarvestNorwegianNegativeMetadataProducesNoCandidates(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: norwegianFixture(t, "negative-passord-metadata.ini"), Path: "negative-passord-metadata.ini"})
	if len(candidates) != 0 {
		t.Fatalf("Norwegian password metadata produced credential candidates: %#v", candidates)
	}
}

// TestStandaloneNorwegianPassordSurfacesForReview confirms a bare Passord
// assignment without identity context is retained (never silently dropped).
func TestStandaloneNorwegianPassordSurfacesForReview(t *testing.T) {
	for _, content := range []string{"Passord=Standalone-Norsk-001!\n", "PASSORD=Standalone-Norsk-002!\n", "passord=Standalone-Norsk-003!\n"} {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "standalone.ini"})
		candidate := candidates[0:0]
		for _, item := range candidates {
			if item.CredentialType == "password" {
				candidate = append(candidate, item)
			}
		}
		if len(candidate) != 1 {
			t.Fatalf("standalone Passord was not retained exactly once: %#v", candidates)
		}
		if candidate[0].Verification != Review {
			t.Fatalf("standalone Passord verification = %q, want review", candidate[0].Verification)
		}
	}
}

func TestHarvestNorwegianUTF8PreservesCharacters(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: norwegianFixture(t, "utf8-norwegian.ini"), Path: "utf8-norwegian.ini"})
	candidate := candidateForValue(candidates, "PåloggingsHemmelighet-123!")
	if candidate == nil {
		t.Fatalf("UTF-8 Norwegian credential was not harvested: %#v", candidates)
	}
	if candidate.Verification != Confirmed {
		t.Fatalf("UTF-8 Norwegian credential verification = %q, want confirmed", candidate.Verification)
	}
	if candidate.Identity != "backup-tjeneste" {
		t.Fatalf("identity = %q, want backup-tjeneste", candidate.Identity)
	}
	if candidate.Domain != "ØKONOMI" {
		t.Fatalf("domain = %q, want ØKONOMI", candidate.Domain)
	}
	if candidate.Value != "PåloggingsHemmelighet-123!" {
		t.Fatalf("value = %q, want PåloggingsHemmelighet-123!", candidate.Value)
	}
}

// TestHarvestNorwegianUTF16LEFixture asserts the on-disk fixture really is
// UTF-16LE, then checks that decoding preserves the exact Norwegian value.
func TestHarvestNorwegianUTF16LEFixture(t *testing.T) {
	content := norwegianFixture(t, "utf16le-norwegian.ini")
	if len(content) < 2 || content[0] != 0xFF || content[1] != 0xFE {
		t.Fatalf("fixture is missing a UTF-16LE BOM: % x", content[:minLen(len(content), 4)])
	}
	if len(content)%2 != 0 {
		t.Fatalf("UTF-16LE fixture has an odd byte length: %d", len(content))
	}
	decoded := utf16.Decode(bytesToUint16(content[2:]))
	if strings.ContainsRune(string(decoded), 0) {
		t.Fatalf("fixture did not decode as UTF-16LE text")
	}
	if !strings.Contains(string(decoded), "Hemmelig-ÆØÅ-123!") {
		t.Fatalf("fixture bytes do not decode to the expected Norwegian value: %q", string(decoded))
	}

	candidates := Harvest(HarvestInput{Content: content, Path: "utf16le-norwegian.ini"})
	candidate := candidateForValue(candidates, "Hemmelig-ÆØÅ-123!")
	if candidate == nil {
		t.Fatalf("UTF-16LE Norwegian credential was not harvested: %#v", candidates)
	}
	if candidate.Verification != Confirmed {
		t.Fatalf("UTF-16LE Norwegian verification = %q, want confirmed", candidate.Verification)
	}
	if candidate.Identity != "deploy" {
		t.Fatalf("UTF-16LE identity = %q, want deploy", candidate.Identity)
	}
	if candidate.Value != "Hemmelig-ÆØÅ-123!" {
		t.Fatalf("UTF-16LE value = %q, want Hemmelig-ÆØÅ-123!", candidate.Value)
	}
}

// TestNorwegianCredentialOracle is the deterministic regression oracle:
// credential positives missed = 0, negative metadata false credentials = 0.
func TestNorwegianCredentialOracle(t *testing.T) {
	type positive struct {
		name    string
		content string
		path    string
		value   string
	}
	seeded := []positive{
		{"password", "password=Oracle-Password-01!\n", "o.txt", "Oracle-Password-01!"},
		{"passwd", "passwd=Oracle-Passwd-02!\n", "o.txt", "Oracle-Passwd-02!"},
		{"pwd", "pwd=Oracle-Pwd-03!\n", "o.txt", "Oracle-Pwd-03!"},
		{"passord", "passord=Oracle-Passord-04!\n", "o.txt", "Oracle-Passord-04!"},
		{"Passord", "Passord=Oracle-Passord-05!\n", "o.txt", "Oracle-Passord-05!"},
		{"PASSORD", "PASSORD=Oracle-Passord-06!\n", "o.txt", "Oracle-Passord-06!"},
		{"AdminPassord", "AdminPassord=Oracle-Admin-07!\n", "o.txt", "Oracle-Admin-07!"},
		{"bruker_passord", "bruker_passord=Oracle-Bruker-08!\n", "o.txt", "Oracle-Bruker-08!"},
		{"DB_PASSORD", "DB_PASSORD=Oracle-DB-09!\n", "o.txt", "Oracle-DB-09!"},
		{"Brukernavn + Passord", "[Default]\nBrukernavn=svc_backup\nPassord=Oracle-BrukerPassord-10!\n", "o.ini", "Oracle-BrukerPassord-10!"},
		{"Domene + Brukernavn + Passord", "[Default]\nDomene=OKONOMI\nBrukernavn=svc_backup\nPassord=Oracle-Domene-11!\n", "o.ini", "Oracle-Domene-11!"},
		{"JSON brukernavn/passord", `{"brukernavn":"svc_json","passord":"Oracle-Json-12!"}`, "o.json", "Oracle-Json-12!"},
		{"YAML brukernavn/passord", "brukernavn: svc_yaml\npassord: Oracle-Yaml-13!\n", "o.yaml", "Oracle-Yaml-13!"},
		{"XML Brukernavn/Passord", "<configuration><Brukernavn>svc_xml</Brukernavn><Passord>Oracle-Xml-14!</Passord></configuration>", "o.xml", "Oracle-Xml-14!"},
		{"UTF-8 ÆØÅ credential", "[Default]\nBrukernavn=backup-tjeneste\nPassord=Påloggings-Hemmelighet-123!\nDomene=ØKONOMI\n", "o.ini", "Påloggings-Hemmelighet-123!"},
	}

	missed := 0
	total := len(seeded)
	for _, item := range seeded {
		candidates := Harvest(HarvestInput{Content: []byte(item.content), Path: item.path})
		if candidateForValue(candidates, item.value) == nil {
			missed++
			t.Errorf("positive %s: credential %q was not surfaced", item.name, item.value)
		}
	}

	// The UTF-16LE fixture is included as a real-bytes positive.
	utf16Candidates := Harvest(HarvestInput{Content: norwegianFixture(t, "utf16le-norwegian.ini"), Path: "utf16le-norwegian.ini"})
	total++
	if candidateForValue(utf16Candidates, "Hemmelig-ÆØÅ-123!") == nil {
		missed++
		t.Errorf("positive UTF-16LE Norwegian: credential was not surfaced")
	}

	negatives := []string{
		"PassordPolicy=Kompleksitet\nPassordLengde=12\nPassordKrav=Store\nPassordHistorikk=24\nPassordKompleksitet=Aktiv\nPassordRegex=^.{12,}$\n",
		"PasswordPolicy=Complexity\nPasswordLength=14\nPasswordHashAlgorithm=PBKDF2\n",
	}
	falseCredentials := 0
	for _, content := range negatives {
		if got := Harvest(HarvestInput{Content: []byte(content), Path: "negative.ini"}); len(got) != 0 {
			falseCredentials += len(got)
			t.Errorf("negative metadata produced false credentials: %#v", got)
		}
	}

	if missed != 0 {
		t.Fatalf("credential positives: %d, missed: %d", total, missed)
	}
	if falseCredentials != 0 {
		t.Fatalf("negative metadata false credentials: %d", falseCredentials)
	}
	t.Logf("oracle: positives=%d surfaced=%d missed=%d false_credentials=%d", total, total-missed, missed, falseCredentials)
}

func hasNorwegianCandidate(candidates []Candidate, verification Verification, value, identity, domain string) bool {
	for _, candidate := range candidates {
		if candidate.Value != value || candidate.Verification != verification {
			continue
		}
		if identity != "" && candidate.Identity != identity {
			continue
		}
		if domain != "" && candidate.Domain != domain {
			continue
		}
		return true
	}
	return false
}

func candidateForValue(candidates []Candidate, value string) *Candidate {
	for i := range candidates {
		if candidates[i].Value == value {
			return &candidates[i]
		}
	}
	return nil
}

func bytesToUint16(content []byte) []uint16 {
	out := make([]uint16, 0, len(content)/2)
	for i := 0; i+1 < len(content); i += 2 {
		out = append(out, uint16(content[i])|uint16(content[i+1])<<8)
	}
	return out
}

func minLen(left, right int) int {
	if left < right {
		return left
	}
	return right
}

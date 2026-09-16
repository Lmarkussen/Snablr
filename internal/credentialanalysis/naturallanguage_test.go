package credentialanalysis

import (
	"strings"
	"testing"
)

// TestNaturalLanguageExpressionOracle is the required positives/negatives oracle
// for the shared credential-expression grammar.
func TestNaturalLanguageExpressionOracle(t *testing.T) {
	positives := []struct {
		name    string
		content string
		path    string
		value   string
	}{
		{"no separator", "Passordet er Secret1!\n", "a.txt", "Secret1!"},
		{"colon", "Passordet er: Secret2!\n", "a.txt", "Secret2!"},
		{"semicolon", "Passordet er; Secret3!\n", "a.txt", "Secret3!"},
		{"equals", "Passordet er=Secret4!\n", "a.txt", "Secret4!"},
		{"dash", "Passordet er - Secret5!\n", "a.txt", "Secret5!"},
		{"definite-less", "Passord er; Secret6!\n", "a.txt", "Secret6!"},
		{"english plain", "password is Secret7!\n", "a.txt", "Secret7!"},
		{"english colon", "Password is: Secret8!\n", "a.txt", "Secret8!"},
		{"english semicolon", "Password is; Secret9!\n", "a.txt", "Secret9!"},
		{"upper case", "PASSORDET ER: Secret10!\n", "a.txt", "Secret10!"},
		{"whitespace tolerant", "Passordet   er;    Secret11!\n", "a.txt", "Secret11!"},
		{"two line", "Passordet er:\nSecret12!\n", "a.txt", "Secret12!"},
		{"two line semicolon", "Passordet er;\nSecret13!\n", "a.txt", "Secret13!"},
		{"utf8 value", "Passordet er; Hemmelig-ÆØÅ-123!\n", "a.txt", "Hemmelig-ÆØÅ-123!"},
		{"norwegian identity pair", "Brukernavn er; svc_backup\nPassordet er; Secret14!\n", "a.txt", "Secret14!"},
		{"english identity pair", "Username is; svc_eng\nPassword is; Secret15!\n", "a.txt", "Secret15!"},
	}
	missed := 0
	for _, test := range positives {
		candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
		candidate := candidateForValue(candidates, test.value)
		if candidate == nil {
			missed++
			t.Errorf("%s: expression value %q was not surfaced: %#v", test.name, test.value, candidates)
			continue
		}
		if candidate.CredentialType != "password" {
			t.Errorf("%s: credential type = %q, want password", test.name, candidate.CredentialType)
		}
	}
	if missed != 0 {
		t.Fatalf("natural-language positives missed: %d", missed)
	}

	// A section-less plain-text file keeps the established top-level policy: the
	// expression is surfaced for review, but identity correlation requires a
	// bounded structural block (a section or a rendered Office block).
	paired := Harvest(HarvestInput{Content: []byte("Brukernavn er; svc_example\nDomene er; KUNDE\nPassordet er; Synthetic-Example-123!\n"), Path: "a.txt"})
	candidate := candidateForValue(paired, "Synthetic-Example-123!")
	if candidate == nil {
		t.Fatalf("paired natural-language credential missing: %#v", paired)
	}
	if candidate.Verification != Review {
		t.Errorf("section-less plain text verification = %q, want review (existing policy)", candidate.Verification)
	}
	// The same expression inside a bounded block correlates and confirms.
	block := Harvest(HarvestInput{Content: []byte("[Default]\nBrukernavn er; svc_example\nDomene er; KUNDE\nPassordet er; Synthetic-Example-123!\n"), Path: "a.ini"})
	confirmed := candidateForValue(block, "Synthetic-Example-123!")
	if confirmed == nil {
		t.Fatalf("bounded block credential missing: %#v", block)
	}
	if confirmed.Identity != "svc_example" || confirmed.Domain != "KUNDE" {
		t.Errorf("identity/domain not correlated: %#v", confirmed)
	}
	if confirmed.Verification != Confirmed {
		t.Errorf("bounded block verification = %q, want confirmed", confirmed.Verification)
	}
	// A standalone expression must still surface (Review at minimum).
	standalone := Harvest(HarvestInput{Content: []byte("Passordet er; Synthetic-Stand Alone?\n"), Path: "a.txt"})
	if candidateForValue(standalone, "Synthetic-Stand") == nil {
		// The value contains a space and is therefore correctly refused as prose.
		t.Logf("standalone spaced value refused as expected: %#v", standalone)
	}
	plain := Harvest(HarvestInput{Content: []byte("Passordet er; Synthetic-StandAlone-123!\n"), Path: "a.txt"})
	solo := candidateForValue(plain, "Synthetic-StandAlone-123!")
	if solo == nil {
		t.Fatalf("standalone expression was not surfaced: %#v", plain)
	}
	if solo.Verification != Review {
		t.Errorf("standalone verification = %q, want review", solo.Verification)
	}
}

// TestNaturalLanguageNegativesOracle proves prose and policy sentences are never
// credentials, in both languages.
func TestNaturalLanguageNegativesOracle(t *testing.T) {
	negatives := []string{
		// Required Norwegian negatives.
		"Passordet er viktig å bytte regelmessig.\n",
		"Passordet er minimum 14 tegn.\n",
		"Passord er påkrevd.\n",
		"Passordet er ikke lagret her.\n",
		"Passordet er definert i policyen.\n",
		"Passord er personlig informasjon.\n",
		"Passordet er skjult.\n",
		"Passordet er deaktivert.\n",
		"Passordet er;\n",
		"Passordet er:   \n",
		// Required English negatives.
		"Password is required.\n",
		"Password is minimum 14 characters.\n",
		"Password is case sensitive.\n",
		"Password is not stored here.\n",
		"Password is encrypted.\n",
		"Password is disabled.\n",
		"Password is defined by policy.\n",
		"The password is changed every 90 days.\n",
		// Placeholder/template values.
		"Passordet er; example\n",
		"Password is; changeme\n",
		"Passordet er; <password>\n",
		"Passordet er; ${PASSWORD}\n",
		"Password is; null\n",
	}
	falsePositives := 0
	for _, content := range negatives {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "a.txt"})
		if len(candidates) != 0 {
			falsePositives += len(candidates)
			t.Errorf("negative produced credential candidates: %q -> %#v", strings.TrimSpace(content), candidates)
		}
	}
	if falsePositives != 0 {
		t.Fatalf("negative false credential candidates: %d", falsePositives)
	}
}

// TestStructuredAssignmentsUnchanged proves the new grammar does not alter
// existing structured assignment behaviour.
func TestStructuredAssignmentsUnchanged(t *testing.T) {
	for _, content := range []string{
		"Password=Secret123!\n",
		"Password: Secret123!\n",
		"Passord=Secret123!\n",
		"Passord: Secret123!\n",
	} {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "a.txt"})
		if candidateForValue(candidates, "Secret123!") == nil {
			t.Errorf("structured assignment regressed for %q: %#v", strings.TrimSpace(content), candidates)
		}
	}
	// The normaliser must leave ordinary assignments and prose untouched.
	for _, text := range []string{
		"Password=Secret123!\n",
		"Passord: hemmelig\n",
		"no credentials in this line\n",
		"",
	} {
		if got := NormalizeCredentialExpressions(text); got != text {
			t.Errorf("normaliser rewrote untouched text: %q -> %q", text, got)
		}
	}
}

// TestNaturalLanguageTwoLineBoundaries proves the next-line form is bounded: a
// blank line separates paragraphs and is never crossed.
func TestNaturalLanguageTwoLineBoundaries(t *testing.T) {
	crossParagraph := "Passordet er;\n\nHidden-123!\n"
	if candidates := Harvest(HarvestInput{Content: []byte(crossParagraph), Path: "a.txt"}); candidateForValue(candidates, "Hidden-123!") != nil {
		t.Fatalf("two-line form crossed a paragraph boundary: %#v", candidates)
	}
	sameParagraph := "Passordet er;\nHidden-123!\n"
	if candidates := Harvest(HarvestInput{Content: []byte(sameParagraph), Path: "a.txt"}); candidateForValue(candidates, "Hidden-123!") == nil {
		t.Fatalf("bounded two-line form was not recognised: %#v", candidates)
	}
}

// TestNaturalLanguageShortExplicitValues proves an explicitly labelled password
// is surfaced even when the value is below the generic inference floor. Poor,
// short, all-digit and PIN-like credentials are still credentials.
func TestNaturalLanguageShortExplicitValues(t *testing.T) {
	positives := []struct {
		name    string
		content string
		value   string
	}{
		{"short numeric", "Passordet er; 8392\n", "8392"},
		{"short mixed", "Passordet er: A7x!\n", "A7x!"},
		{"english short numeric", "Password is; 7319\n", "7319"},
		{"short without separator", "Passordet er 8392\n", "8392"},
		{"short two-line", "Passordet er;\n7319\n", "7319"},
	}
	for _, test := range positives {
		candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: "a.txt"})
		candidate := candidateForValue(candidates, test.value)
		if candidate == nil {
			t.Errorf("%s: short explicit value %q was not surfaced: %#v", test.name, test.value, candidates)
			continue
		}
		if candidate.CredentialType != "password" {
			t.Errorf("%s: credential type = %q, want password", test.name, candidate.CredentialType)
		}
		// A standalone short value must not be promoted by the relaxation.
		if candidate.Verification != Review {
			t.Errorf("%s: standalone verification = %q, want review", test.name, candidate.Verification)
		}
	}

	// Bounded structural context still decides Confirmed, unchanged by the floor.
	confirmed := Harvest(HarvestInput{
		Content: []byte("[Default]\nBrukernavn er; user1\nPassordet er; 8392\n"),
		Path:    "a.ini",
	})
	block := candidateForValue(confirmed, "8392")
	if block == nil {
		t.Fatalf("short value in a bounded block was not surfaced: %#v", confirmed)
	}
	if block.Verification == Review {
		t.Errorf("short value in a bounded block stayed at review: %#v", block)
	}
	if block.Identity != "user1" {
		t.Errorf("identity correlation regressed: %#v", block)
	}
}

// TestNaturalLanguagePrefixExpressions proves a bounded expression may follow
// ordinary prefix text on the same line, and that the prefix never leaks into
// the value.
func TestNaturalLanguagePrefixExpressions(t *testing.T) {
	positives := []struct {
		name    string
		content string
		value   string
	}{
		{"norwegian prefix", "Lokal innlogging. Passordet er; Synthetic-One-123!\n", "Synthetic-One-123!"},
		{"english prefix", "Login information. Password is; Synthetic-Two-123!\n", "Synthetic-Two-123!"},
		{"norwegian prefix short", "Lokal innlogging. Passordet er; 8392\n", "8392"},
	}
	for _, test := range positives {
		candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: "a.txt"})
		if candidateForValue(candidates, test.value) == nil {
			t.Errorf("%s: prefixed expression value %q was not surfaced: %#v", test.name, test.value, candidates)
			continue
		}
		for _, candidate := range candidates {
			if strings.ContainsAny(candidate.Value, " ") {
				t.Errorf("%s: prefix text leaked into the value: %#v", test.name, candidate)
			}
		}
	}
}

// TestNaturalLanguageSubjectExpressions proves a bounded subject phrase between
// the label and the copula is recognised without creating subject-specific
// credential types.
func TestNaturalLanguageSubjectExpressions(t *testing.T) {
	positives := []struct {
		name    string
		content string
		value   string
	}{
		{"norwegian subject", "Passordet for nettverket er; Synthetic-Net-123!\n", "Synthetic-Net-123!"},
		{"norwegian acronym subject", "Passordet for VPN er; Synthetic-VPN-123!\n", "Synthetic-VPN-123!"},
		{"english subject", "Password for VPN is; Synthetic-English-123!\n", "Synthetic-English-123!"},
		{"norwegian subject short", "Passordet for VPN er; 8392\n", "8392"},
	}
	for _, test := range positives {
		candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: "a.txt"})
		candidate := candidateForValue(candidates, test.value)
		if candidate == nil {
			t.Errorf("%s: subject expression value %q was not surfaced: %#v", test.name, test.value, candidates)
			continue
		}
		if candidate.CredentialType != "password" {
			t.Errorf("%s: credential type = %q, want password (no subject-specific types)", test.name, candidate.CredentialType)
		}
	}
}

// TestNaturalLanguageIdentityDefiniteForms proves the Norwegian definite forms of
// the identity labels map onto the shared identity role.
func TestNaturalLanguageIdentityDefiniteForms(t *testing.T) {
	wanted := map[string]FieldRole{
		"brukernavn": FieldRoleIdentity, "brukernavnet": FieldRoleIdentity,
		"bruker": FieldRoleIdentity, "brukeren": FieldRoleIdentity,
		"konto": FieldRoleIdentity, "username": FieldRoleIdentity,
		"user": FieldRoleIdentity, "account": FieldRoleIdentity,
	}
	for label, role := range wanted {
		if got := ClassifyFieldName(label); got != role {
			t.Errorf("identity label %q = %v, want %v", label, got, role)
		}
	}
	if got := ClassifyFieldName("passordet"); got != FieldRolePassword {
		t.Errorf("password label passordet = %v, want password", got)
	}
	if got := ClassifyFieldName("domene"); got != FieldRoleDomain {
		t.Errorf("domain label domene = %v, want domain", got)
	}

	// The definite forms must correlate exactly like the base forms.
	for _, test := range []struct{ label, identity string }{
		{"Brukernavnet", "user2"},
		{"Brukeren", "user3"},
	} {
		block := Harvest(HarvestInput{
			Content: []byte("[Default]\n" + test.label + " er; " + test.identity + "\nPassordet er; A7x!\n"),
			Path:    "a.ini",
		})
		candidate := candidateForValue(block, "A7x!")
		if candidate == nil {
			t.Errorf("%s: credential not surfaced: %#v", test.label, block)
			continue
		}
		if candidate.Identity != test.identity {
			t.Errorf("%s: identity = %q, want %q", test.label, candidate.Identity, test.identity)
		}
	}
}

// TestNaturalLanguageFollowUpNegativesOracle proves the widened grammar still
// refuses prose, policy sentences and subject-shaped prose in both languages.
func TestNaturalLanguageFollowUpNegativesOracle(t *testing.T) {
	negatives := []string{
		"Passordet er viktig.\n",
		"Passordet er påkrevd.\n",
		"Passordet er kort.\n",
		"Passordet er deaktivert.\n",
		"Passordet er fire tegn langt.\n",
		"Passordet er definert av policy.\n",
		"Password is required.\n",
		"Password is disabled.\n",
		"Password is short.\n",
		"Password is defined by policy.\n",
		"Password is case-sensitive.\n",
		"Vi snakker om passord i denne teksten.\n",
		"Dette dokumentet sier at passord er viktig.\n",
		"Passordet for brukere må endres hver måned.\n",
		"Passordet for systemet er definert av policy.\n",
		"Password for users must be changed monthly.\n",
	}
	falsePositives := 0
	for _, content := range negatives {
		candidates := Harvest(HarvestInput{Content: []byte(content), Path: "a.txt"})
		if len(candidates) != 0 {
			falsePositives += len(candidates)
			t.Errorf("negative produced credential candidates: %q -> %#v", strings.TrimSpace(content), candidates)
		}
	}
	if falsePositives != 0 {
		t.Fatalf("negative false credential candidates: %d", falsePositives)
	}
}

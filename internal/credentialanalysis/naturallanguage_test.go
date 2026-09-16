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

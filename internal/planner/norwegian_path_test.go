package planner

import (
	"strings"
	"testing"
)

// TestNorwegianCredentialPathVocabulary proves the containing folder name
// reaches path discovery: a Norwegian credential-list directory must score as
// credential material even for an otherwise unremarkable file name.
func TestNorwegianCredentialPathVocabulary(t *testing.T) {
	for _, path := range []string{
		"PasswordLists/PasswordList.txt",
		"IT/Innlogging/notater.txt",
		"Dokumenter/Pålogging/oversikt.txt",
	} {
		score, reasons := scoreFile(FileInput{Host: "fs01", Share: "share", Path: path, Extension: ".txt"})
		joined := strings.Join(reasons, "; ")
		if !strings.Contains(joined, "path suggests credential or secret material") {
			t.Errorf("%s: path hint missing (score=%d reasons=%v)", path, score, reasons)
		}
	}
	// A plain documentation path must not claim the credential-material hint.
	if _, reasons := scoreFile(FileInput{Host: "fs01", Share: "share", Path: "Dokumentasjon/rapport.txt", Extension: ".txt"}); strings.Join(reasons, "; ") != "base file priority" {
		t.Errorf("unrelated path gained credential hints: %v", reasons)
	}
	// Generic account wording is deliberately not treated as credential
	// material by path alone: "Kontoer" hints at accounts, not passwords.
	if _, reasons := scoreFile(FileInput{Host: "fs01", Share: "share", Path: "Kontoer/kontoliste.txt", Extension: ".txt"}); strings.Contains(strings.Join(reasons, "; "), "path suggests credential or secret material") {
		t.Errorf("generic account path was promoted to credential material: %v", reasons)
	}
}

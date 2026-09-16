package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/config"
	"snablr/internal/scanner"
)

// TestFilenameOnlyPasswordListIsReportedButNeverExported pins the discovery
// contract for the live filename shape: "PasswordList.txt" must appear in the
// safe reports as a review signal, while a filename alone never becomes a
// credential record in the sensitive export.
func TestFilenameOnlyPasswordListIsReportedButNeverExported(t *testing.T) {
	finding := scanner.Finding{
		RuleID:          "filename.norwegian_password_list_keywords",
		RuleName:        "Norwegian Password List Keywords",
		Severity:        "medium",
		Confidence:      "low",
		ConfidenceScore: 18,
		Category:        "credentials",
		TriageClass:     "weak-review",
		Actionable:      false,
		SignalType:      "filename",
		Match:           "Passordliste",
		MatchedText:     "Passordliste",
		FilePath:        "Dokumenter/PasswordList.txt",
		Host:            "fs01",
		Share:           "share",
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	credsPath := filepath.Join(dir, "creds.txt")
	writer, err := NewWriter(config.OutputConfig{
		Format: "json,html", NoTUI: true, JSONOut: jsonPath, HTMLOut: htmlPath, CredsOut: credsPath, Pretty: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteFinding(finding); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{"json": jsonPath, "html": htmlPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "filename.norwegian_password_list_keywords") {
			t.Errorf("%s report does not contain the filename discovery finding", name)
		}
		if !strings.Contains(string(raw), "PasswordList.txt") {
			t.Errorf("%s report does not name the discovered file", name)
		}
	}

	creds, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(creds), "No high-confidence credentials were exported") {
		t.Errorf("filename-only discovery produced a credential export:\n%s", creds)
	}
}

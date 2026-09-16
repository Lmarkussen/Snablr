package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"snablr/internal/config"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func norwegianConfirmedCandidate() credentialanalysis.Candidate {
	return credentialanalysis.Candidate{
		Verification:    credentialanalysis.Confirmed,
		CredentialType:  "password",
		Domain:          "ØKONOMI",
		Identity:        "svc_backup",
		Value:           "Påloggings-Hemmelighet-123!",
		Path:            `\\fs01\share\okonomi\CustomSettings.ini`,
		ValidationBasis: "structured configuration section",
	}
}

func norwegianIdentityCandidate() credentialanalysis.Candidate {
	return credentialanalysis.Candidate{
		Verification:    credentialanalysis.Confirmed,
		CredentialType:  "password",
		Domain:          "ØKONOMI",
		Identity:        "påloggingsbruker-æøå",
		Value:           "Andre-Hemmelighet-æøå-456!",
		Path:            `\\fs01\share\okonomi\passord.ini`,
		ValidationBasis: "structured configuration section",
	}
}

// TestCredsWriterExportsSyntheticNorwegianCredential validates the sensitive
// creds-out projection: semantic type stays "password", Norwegian domain and
// identity render as UTF-8, and the export file is created mode 0600.
func TestCredsWriterExportsSyntheticNorwegianCredential(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.txt")

	writer, err := NewWriter(config.OutputConfig{Format: "console", NoTUI: true, CredsOut: credsPath})
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	recorder, ok := writer.(scanner.CredentialCandidateSink)
	if !ok {
		t.Fatalf("writer does not implement the credential candidate sink")
	}
	if err := recorder.RecordCredentialCandidate(norwegianConfirmedCandidate()); err != nil {
		t.Fatalf("RecordCredentialCandidate returned error: %v", err)
	}
	if err := recorder.RecordCredentialCandidate(norwegianIdentityCandidate()); err != nil {
		t.Fatalf("RecordCredentialCandidate returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	info, err := os.Stat(credsPath)
	if err != nil {
		t.Fatalf("stat creds export: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("creds export permissions = %o, want 600", got)
	}

	raw, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatalf("read creds export: %v", err)
	}
	output := string(raw)
	for _, want := range []string{
		"Type: password",
		"Domain: ØKONOMI",
		"Identity: svc_backup",
		"Identity: påloggingsbruker-æøå",
		"Value: Påloggings-Hemmelighet-123!",
		"Value: Andre-Hemmelighet-æøå-456!",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("creds export missing %q, got:\n%s", want, output)
		}
	}
	if !utf8.Valid(raw) {
		t.Fatalf("creds export is not valid UTF-8")
	}
}

// TestSafeReportersRenderNorwegianUTF8 verifies the safe HTML/JSON reports keep
// Norwegian metadata intact and valid UTF-8 while never leaking the value.
func TestSafeReportersRenderNorwegianUTF8(t *testing.T) {
	candidates := []credentialanalysis.Candidate{norwegianConfirmedCandidate(), norwegianIdentityCandidate()}

	var jsonBuf strings.Builder
	jsonWriter := NewJSONWriter(&jsonBuf, nil, true)
	for _, candidate := range candidates {
		if err := jsonWriter.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := jsonWriter.Close(); err != nil {
		t.Fatal(err)
	}
	jsonOut := jsonBuf.String()
	for _, candidate := range candidates {
		if strings.Contains(jsonOut, candidate.Value) {
			t.Fatalf("safe JSON leaked the credential value")
		}
	}
	if !strings.Contains(jsonOut, "ØKONOMI") || !strings.Contains(jsonOut, "svc_backup") || !strings.Contains(jsonOut, "påloggingsbruker-æøå") {
		t.Fatalf("safe JSON did not preserve Norwegian metadata: %s", jsonOut)
	}
	if !utf8.Valid([]byte(jsonOut)) {
		t.Fatalf("safe JSON is not valid UTF-8")
	}

	var htmlBuf strings.Builder
	htmlWriter, err := NewHTMLWriter(&htmlBuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if err := htmlWriter.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := htmlWriter.Close(); err != nil {
		t.Fatal(err)
	}
	htmlOut := htmlBuf.String()
	for _, candidate := range candidates {
		if strings.Contains(htmlOut, candidate.Value) {
			t.Fatalf("safe HTML leaked the credential value")
		}
	}
	if !strings.Contains(htmlOut, "svc_backup") || !strings.Contains(htmlOut, "påloggingsbruker-æøå") {
		t.Fatalf("safe HTML did not preserve Norwegian metadata")
	}
	if !utf8.Valid([]byte(htmlOut)) {
		t.Fatalf("safe HTML is not valid UTF-8")
	}
}

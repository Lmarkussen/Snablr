package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"snablr/internal/archiveinspect"
	"snablr/internal/config"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// harvestOfficeFixture drives the real extraction -> shared harvester path for
// one Office fixture, without going through a live share.
func harvestOfficeFixture(t *testing.T, name string) []credentialanalysis.Candidate {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "office-credential-regression", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	extension := strings.ToLower(filepath.Ext(name))
	if extension != ".docx" && extension != ".xlsx" && extension != ".pptx" && extension != ".zip" {
		// Delimited exports are harvested directly.
		return credentialanalysis.Harvest(credentialanalysis.HarvestInput{
			Content: content,
			Path:    name,
		})
	}
	result, err := archiveinspect.InspectZIP(content, extension, archiveinspect.Options{
		Enabled:              true,
		AutoZIPMaxSize:       10 * 1024 * 1024,
		MaxZIPSize:           10 * 1024 * 1024,
		MaxMembers:           64,
		MaxMemberBytes:       4 * 1024 * 1024,
		MaxTotalUncompressed: 8 * 1024 * 1024,
	}, map[string]struct{}{".xml": {}})
	if err != nil {
		t.Fatalf("InspectZIP(%s) returned error: %v", name, err)
	}
	var candidates []credentialanalysis.Candidate
	for _, member := range result.Members {
		candidates = append(candidates, credentialanalysis.Harvest(credentialanalysis.HarvestInput{
			Content: member.Content,
			Path:    name + "!" + member.Path,
		})...)
	}
	return candidates
}

// TestOfficeCredentialsRenderInCredsOut verifies that Office-derived Norwegian
// credentials reach the sensitive export with semantic type "password",
// correct provenance, mode 0600, and intact UTF-8.
func TestOfficeCredentialsRenderInCredsOut(t *testing.T) {
	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.txt")
	writer, err := NewWriter(config.OutputConfig{Format: "console", NoTUI: true, CredsOut: credsPath})
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	recorder, ok := writer.(scanner.CredentialCandidateSink)
	if !ok {
		t.Fatal("writer does not implement the credential candidate sink")
	}

	var candidates []credentialanalysis.Candidate
	for _, fixture := range []string{
		"passordliste.docx",
		"norwegian-docx-pair.docx",
		"norwegian-docx-utf8.docx",
		"norwegian-xlsx-pair.xlsx",
		"norwegian-xlsx-utf8.xlsx",
		"norwegian-pptx-pair.pptx",
		"norwegian-credentials.csv",
		"norwegian-credentials.tsv",
	} {
		candidates = append(candidates, harvestOfficeFixture(t, fixture)...)
	}
	report := credentialanalysis.Analyze(candidates)
	if len(report.Candidates) == 0 {
		t.Fatal("no Office-derived credential candidates were analyzed")
	}
	for _, candidate := range report.Candidates {
		if err := recorder.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	if !utf8.Valid(raw) {
		t.Fatal("creds export is not valid UTF-8")
	}
	output := string(raw)
	for _, want := range []string{
		"Type: password",
		"Identity: svc_word",
		"Value: Word-Hemmelig-999!",
		"Identity: backup-tjeneste",
		"Value: Påloggings-Hemmelighet-ÆØÅ-123!",
		"Value: Regnskap-ÆØÅ-123!",
		"Value: Excel-Hemmelig-123!",
		"Value: PowerPoint-Hemmelig-123!",
		"Value: Csv-Hemmelig-123!",
		"Value: Tsv-Hemmelig-123!",
		"passordliste.docx!word/document.xml",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("creds export missing %q, got:\n%s", want, output)
		}
	}
}

// TestOfficeSafeReportsKeepPrivacyAndEncoding verifies the safe HTML/JSON
// reports classify Office-derived material without leaking values or UTF-8.
func TestOfficeSafeReportsKeepPrivacyAndEncoding(t *testing.T) {
	candidates := credentialanalysis.Analyze(harvestOfficeFixture(t, "norwegian-docx-utf8.docx")).Candidates
	if len(candidates) == 0 {
		t.Fatal("no candidates harvested from the UTF-8 Office fixture")
	}

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
	if strings.Contains(jsonOut, "Påloggings-Hemmelighet-ÆØÅ-123!") {
		t.Fatal("safe JSON leaked an Office credential value")
	}
	if !strings.Contains(jsonOut, "backup-tjeneste") || !strings.Contains(jsonOut, "ØKONOMI") {
		t.Fatalf("safe JSON lost Norwegian metadata: %s", jsonOut)
	}
	if !utf8.Valid([]byte(jsonOut)) {
		t.Fatal("safe JSON is not valid UTF-8")
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
	if strings.Contains(htmlOut, "Påloggings-Hemmelighet-ÆØÅ-123!") {
		t.Fatal("safe HTML leaked an Office credential value")
	}
	if !strings.Contains(htmlOut, "backup-tjeneste") {
		t.Fatal("safe HTML lost Norwegian identity metadata")
	}
	if !utf8.Valid([]byte(htmlOut)) {
		t.Fatal("safe HTML is not valid UTF-8")
	}
}

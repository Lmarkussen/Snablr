package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func readNorwegianFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "norwegian-credential-regression", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

// TestEngineHarvestsNorwegianCredentials drives the full engine harvester path
// (including UTF-16 text normalization) for Norwegian credential fields.
func TestEngineHarvestsNorwegianCredentials(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		fixture      string
		value        string
		identity     string
		domain       string
		verification credentialanalysis.Verification
	}{
		{
			name:         "UTF-8 structural identity",
			path:         "utf8-norwegian.ini",
			fixture:      "utf8-norwegian.ini",
			value:        "PåloggingsHemmelighet-123!",
			identity:     "backup-tjeneste",
			domain:       "ØKONOMI",
			verification: credentialanalysis.Confirmed,
		},
		{
			name:         "UTF-16LE Norwegian",
			path:         "utf16le-norwegian.ini",
			fixture:      "utf16le-norwegian.ini",
			value:        "Hemmelig-ÆØÅ-123!",
			identity:     "deploy",
			verification: credentialanalysis.Confirmed,
		},
		{
			name:         "JSON brukernavn/passord",
			path:         "credentials.json",
			fixture:      "credentials.json",
			value:        "Json-Hemmelig-123!",
			identity:     "svc_json",
			verification: credentialanalysis.Confirmed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := &recordingCandidateSink{}
			engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
			engine.SetCredentialCandidateSink(collector)
			content := readNorwegianFixture(t, test.fixture)
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
				FilePath: test.path, Name: filepath.Base(test.path), Extension: filepath.Ext(test.path), Size: int64(len(content)),
			}, content)
			if evaluation.Skipped {
				t.Fatalf("file unexpectedly skipped: %s", evaluation.SkipReason)
			}
			if !hasCandidateValue(collector.candidates, test.value, test.identity, test.domain, test.verification) {
				t.Fatalf("expected Norwegian credential candidate, got %#v", collector.candidates)
			}
		})
	}
}

package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func readDeploymentFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "deployment-credential-regression", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

func TestEngineHarvestsDeploymentCredentialsFromLooseFiles(t *testing.T) {
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
			name:         "CustomSettings.ini",
			path:         "CustomSettings.ini",
			fixture:      "CustomSettings.ini",
			value:        "LafDm-Deployment-Test-001!",
			identity:     "Administrator",
			domain:       "CONTOSO",
			verification: credentialanalysis.Confirmed,
		},
		{
			name:         "Bootstrap.ini",
			path:         "Bootstrap.ini",
			fixture:      "Bootstrap.ini",
			value:        "Bootstrap-Test-005!",
			identity:     "deployuser",
			domain:       "CONTOSO",
			verification: credentialanalysis.Confirmed,
		},
		{
			name:         "unattend.xml",
			path:         "unattend.xml",
			fixture:      "unattend.xml",
			value:        "AutoLogon-Test-003!",
			identity:     "Administrator",
			domain:       "CONTOSO",
			verification: credentialanalysis.Confirmed,
		},
		{
			name:         "misleading extension",
			path:         "unattned.xlm",
			fixture:      "unattned.xlm",
			value:        "Misleading-Extension-Test-006!",
			identity:     "Administrator",
			verification: credentialanalysis.Confirmed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := &recordingCandidateSink{}
			engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
			engine.SetCredentialCandidateSink(collector)
			content := readDeploymentFixture(t, test.fixture)
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
				FilePath: test.path, Name: filepath.Base(test.path), Extension: filepath.Ext(test.path), Size: int64(len(content)),
			}, content)
			if evaluation.Skipped {
				t.Fatalf("file unexpectedly skipped: %s", evaluation.SkipReason)
			}
			if !hasCandidateValue(collector.candidates, test.value, test.identity, test.domain, test.verification) {
				t.Fatalf("expected deployment credential candidate, got %#v", collector.candidates)
			}
		})
	}
}

func TestEngineHarvestsDeploymentCredentialsFromArchive(t *testing.T) {
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	files := map[string][]byte{
		"CustomSettings.ini":               readDeploymentFixture(t, "CustomSettings.ini"),
		"Windows/Panther/autounattend.xml": readDeploymentFixture(t, "unattend.xml"),
	}
	for name, content := range files {
		writer, err := zipWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: "deployment.zip", Name: "deployment.zip", Extension: ".zip", Size: int64(archive.Len()),
	}, archive.Bytes())
	if evaluation.Skipped {
		t.Fatalf("archive unexpectedly skipped: %s", evaluation.SkipReason)
	}
	if !hasCandidateValue(collector.candidates, "LafDm-Deployment-Test-001!", "Administrator", "CONTOSO", credentialanalysis.Confirmed) {
		t.Fatalf("archive CustomSettings credential missing: %#v", collector.candidates)
	}
	if !hasCandidateValue(collector.candidates, "AutoLogon-Test-003!", "Administrator", "CONTOSO", credentialanalysis.Confirmed) {
		t.Fatalf("archive unattend credential missing: %#v", collector.candidates)
	}
	for _, candidate := range collector.candidates {
		if candidate.Container != "deployment.zip" {
			t.Fatalf("archive provenance not preserved: %#v", candidate)
		}
	}
}

func hasCandidateValue(candidates []credentialanalysis.Candidate, value, identity, domain string, verification credentialanalysis.Verification) bool {
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

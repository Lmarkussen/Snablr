package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/wiminspect"
	"snablr/pkg/logx"
)

func TestEngineHarvestsDeploymentCredentialsFromWIM(t *testing.T) {
	wimlib, err := exec.LookPath("wimlib-imagex")
	if err != nil {
		t.Skip("wimlib-imagex not available")
	}

	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "Windows", "Panther"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "CustomSettings.ini"), readDeploymentFixture(t, "CustomSettings.ini"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "Windows", "Panther", "autounattend.xml"), readDeploymentFixture(t, "unattend.xml"), 0o600); err != nil {
		t.Fatal(err)
	}

	wimPath := filepath.Join(root, "deployment.wim")
	cmd := exec.Command(wimlib, "capture", source, wimPath, "Deployment Credential Regression", "--compress=none")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create WIM: %v\n%s", err, output)
	}
	stat, err := os.Stat(wimPath)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(wimPath)
	if err != nil {
		t.Fatal(err)
	}

	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: stat.Size() + 1,
			MaxWIMSize:     stat.Size() + 1,
		},
	}, &rules.Manager{}, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: wimPath, Name: "deployment.wim", Extension: ".wim", Size: stat.Size(),
	}, content)
	if evaluation.Skipped {
		t.Fatalf("WIM unexpectedly skipped: %s", evaluation.SkipReason)
	}
	if evaluation.Cleanup != nil {
		defer func() { _ = evaluation.Cleanup() }()
	}
	if !hasCandidateValue(collector.candidates, "LafDm-Deployment-Test-001!", "Administrator", "CONTOSO", credentialanalysis.Confirmed) {
		t.Fatalf("WIM CustomSettings credential missing: %#v", collector.candidates)
	}
	if !hasCandidateValue(collector.candidates, "AutoLogon-Test-003!", "Administrator", "CONTOSO", credentialanalysis.Confirmed) {
		t.Fatalf("WIM autologon credential missing: %#v", collector.candidates)
	}
	for _, candidate := range collector.candidates {
		if candidate.Container != wimPath {
			t.Fatalf("WIM provenance not preserved: %#v", candidate)
		}
	}
}

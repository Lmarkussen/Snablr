package scanner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/artifactbundle"
	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/rules"
	"snablr/internal/systemkey"
	"snablr/internal/wiminspect"
	"snablr/pkg/logx"
)

func TestEngineIntegratesLooseSAMSystemBundleWithoutHashOutput(t *testing.T) {
	current := uint32(1)
	systemBytes := testfixture.Build(testfixture.Spec{
		Current: &current, IncludeSelect: true, IncludeCurrent: true,
		IncludeControl: true, IncludeLSA: true,
		Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"},
	})
	systemHive, err := registryhive.Open(bytes.NewReader(systemBytes), int64(len(systemBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	// This is a known test vector; it must not appear in scanner evidence.
	knownHash := "8846f7eaee8fb117ad06bdd830b7586c"
	var hash [16]byte
	for i, value := range []byte{0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c} {
		hash[i] = value
	}
	samBytes := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot.BootKey, KeyRevision: 1, IncludeDomain: true,
		Accounts: []testfixture.SAMAccount{{RID: 500, Username: "localadmin", NTHash: hash, HashRevision: 1}}})

	coordinator := artifactbundle.New(artifactbundle.Options{})
	defer coordinator.Close()
	engine := NewEngine(Options{BundleCoordinator: coordinator, SAMMaxBytes: 32 << 20, SYSTEMMaxBytes: 64 << 20}, &rules.Manager{}, nil, logx.New("error"))
	base := FileMetadata{Host: "host", Share: "share", Source: "smb"}
	samEval := engine.EvaluateContext(context.Background(), FileMetadata{Host: base.Host, Share: base.Share, Source: base.Source, FilePath: "/backup/SAM", Name: "SAM"}, samBytes)
	if len(samEval.BinaryArtifacts) != 0 {
		t.Fatalf("accepted SAM artifact remained worker-owned")
	}
	systemEval := engine.EvaluateContext(context.Background(), FileMetadata{Host: base.Host, Share: base.Share, Source: base.Source, FilePath: "/backup/SYSTEM", Name: "SYSTEM"}, systemBytes)
	if len(systemEval.BinaryArtifacts) != 0 {
		t.Fatalf("accepted SYSTEM artifact remained worker-owned")
	}
	var parsed *Finding
	for i := range systemEval.Findings {
		if systemEval.Findings[i].RuleID == samBundleFindingRuleID {
			parsed = &systemEval.Findings[i]
		}
	}
	if parsed == nil || !parsed.Actionable || parsed.SignalType != "validated" {
		t.Fatalf("validated SAM finding missing: %#v", systemEval.Findings)
	}
	joined := strings.Join([]string{parsed.MatchedText, parsed.Snippet, parsed.Context, parsed.ContextRedacted, parsed.MatchedTextRedacted}, "\n")
	if strings.Contains(strings.ToLower(joined), knownHash) {
		t.Fatal("raw test hash leaked into scanner finding")
	}
}

func TestEngineDoesNotClaimRecoveryForMarkerSAMSystem(t *testing.T) {
	coordinator := artifactbundle.New(artifactbundle.Options{})
	defer coordinator.Close()
	engine := NewEngine(Options{BundleCoordinator: coordinator}, &rules.Manager{}, nil, logx.New("error"))
	for _, item := range []struct {
		path string
		kind string
	}{
		{path: "/backup/SAM", kind: "SAM"},
		{path: "/backup/SYSTEM", kind: "SYSTEM"},
	} {
		evaluation := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: item.path, Name: item.kind}, []byte("synthetic marker"))
		for _, finding := range evaluation.Findings {
			if finding.RuleID == samBundleFindingRuleID {
				t.Fatalf("marker generated validated finding: %#v", finding)
			}
		}
	}
}

func TestEngineIntegratesValidSyntheticWIM(t *testing.T) {
	if _, err := exec.LookPath("wimlib-imagex"); err != nil {
		t.Skip("wimlib-imagex not available")
	}
	current := uint32(1)
	systemBytes := testfixture.Build(testfixture.Spec{
		Current: &current, IncludeSelect: true, IncludeCurrent: true,
		IncludeControl: true, IncludeLSA: true,
		Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"},
	})
	systemHive, err := registryhive.Open(bytes.NewReader(systemBytes), int64(len(systemBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	samBytes := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot.BootKey, KeyRevision: 2, IncludeDomain: true,
		Accounts: []testfixture.SAMAccount{{RID: 500, Username: "wim_test_admin", NTHash: [16]byte{1, 2, 3}, HashRevision: 2}}})
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "Windows", "System32", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "Windows", "System32", "config", "SAM"), samBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "Windows", "System32", "config", "SYSTEM"), systemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	wimPath := filepath.Join(t.TempDir(), "valid-sam-system.wim")
	if output, err := exec.Command("wimlib-imagex", "capture", tree, wimPath, "SnablrTest", "--compress=none").CombinedOutput(); err != nil {
		t.Fatalf("capture WIM: %v: %s", err, output)
	}
	wimBytes, err := os.ReadFile(wimPath)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := artifactbundle.New(artifactbundle.Options{})
	defer coordinator.Close()
	engine := NewEngine(Options{BundleCoordinator: coordinator, WIM: wiminspect.Options{Enabled: true, AutoWIMMaxSize: int64(len(wimBytes)) + 1, MaxWIMSize: int64(len(wimBytes)) + 1}}, &rules.Manager{}, nil, logx.New("error"))
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: "valid-sam-system.wim", Name: "valid-sam-system.wim", Extension: ".wim", Size: int64(len(wimBytes))}, wimBytes)
	defer func() { _ = evaluation.Cleanup() }()
	if len(evaluation.BinaryArtifacts) != 0 {
		t.Fatalf("accepted WIM artifacts remained worker-owned")
	}
	for _, finding := range evaluation.Findings {
		if finding.RuleID == samBundleFindingRuleID {
			if finding.SignalType != "validated" || !finding.Actionable || !strings.Contains(finding.MatchedText, "accounts recovered: 1") {
				t.Fatalf("unexpected WIM bundle finding: %#v", finding)
			}
			return
		}
	}
	t.Fatalf("valid WIM bundle finding missing: %#v", evaluation.Findings)
}

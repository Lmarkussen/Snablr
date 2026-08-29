package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/artifact"
	"snablr/internal/artifactbundle"
	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/state"
	"snablr/internal/systemkey"
	"snablr/pkg/logx"
)

func TestConfiguredShareFallbackUsesExplicitAllowedShares(t *testing.T) {
	cfg := config.ScanConfig{
		Share:        []string{"NETLOGON", "netlogon", "IPC$"},
		ExcludeShare: []string{"IPC$"},
	}
	got := configuredShareFallback(cfg)
	if len(got) != 1 || got[0].Name != "NETLOGON" {
		t.Fatalf("configuredShareFallback = %#v, want one NETLOGON share", got)
	}
}

func TestConfiguredShareFallbackHonoursOnlyADShares(t *testing.T) {
	cfg := config.ScanConfig{
		Share:        []string{"Public", "SYSVOL"},
		OnlyADShares: true,
	}
	got := configuredShareFallback(cfg)
	if len(got) != 1 || got[0].Name != "SYSVOL" {
		t.Fatalf("configuredShareFallback = %#v, want one SYSVOL share", got)
	}
}

func TestIncrementalSemanticsFingerprintChangesForInspectionSettings(t *testing.T) {
	t.Parallel()
	base := config.Default()
	first := scanSemanticsFingerprint(base, nil)
	base.WIM.MaxMembers++
	second := scanSemanticsFingerprint(base, nil)
	if first == second {
		t.Fatal("expected WIM inspection setting to invalidate incremental semantics")
	}
}

func TestCredentialContextIDsExcludeSecretsAndSeparateAuthModes(t *testing.T) {
	t.Parallel()
	password := state.CredentialContextID("password", "user", "domain")
	hash := state.CredentialContextID("ntlm-hash", "user", "domain")
	if password == hash {
		t.Fatal("password and NTLM-hash contexts should remain distinguishable")
	}
	if len(password) != len("ctx-")+64 {
		t.Fatalf("unexpected opaque context ID %q", password)
	}
}

func TestIncrementalScanEnabledByStateDirectoryOrExplicitFlag(t *testing.T) {
	t.Parallel()
	if incrementalScanEnabled(config.Default()) {
		t.Fatal("default scan must not enable incremental state")
	}
	cfg := config.Default()
	cfg.Scan.StateDir = "./state"
	if !incrementalScanEnabled(cfg) {
		t.Fatal("state directory should enable incremental state")
	}
	cfg = config.Default()
	cfg.Scan.Incremental = true
	if !incrementalScanEnabled(cfg) {
		t.Fatal("explicit incremental mode should be detected")
	}
}

func TestCollectBundleDependenciesRehydratesOnlySameOriginPartners(t *testing.T) {
	key := artifactbundle.BundleKey{Host: "host", Share: "share", Scope: "Windows/System32/config", Context: "loose"}
	otherOrigin := key
	otherOrigin.Scope = "Windows/Other/config"
	candidate := func(path string) bundleCandidate {
		return bundleCandidate{remote: smb.RemoteFile{Host: "host", Share: "share", Path: path}}
	}

	changed := map[artifactbundle.BundleKey]map[artifact.Kind]bool{
		key: {artifact.KindSECURITY: true},
	}
	candidates := map[artifactbundle.BundleKey]map[artifact.Kind]bundleCandidate{
		key: {
			artifact.KindSYSTEM: candidate("Windows/System32/config/SYSTEM"),
		},
		otherOrigin: {
			artifact.KindSYSTEM: candidate("Windows/Other/config/SYSTEM"),
		},
	}
	rehydrated := make(map[artifactbundle.BundleKey]map[artifact.Kind]bool)
	got := collectBundleDependencies(changed, candidates, rehydrated)
	if len(got) != 1 || got[0].remote.Path != "Windows/System32/config/SYSTEM" {
		t.Fatalf("dependencies = %#v, want only same-origin SYSTEM", got)
	}
	if again := collectBundleDependencies(changed, candidates, rehydrated); len(again) != 0 {
		t.Fatalf("second collection = %#v, want no duplicate dependency", again)
	}
}

func TestCollectBundleDependenciesCoversChangedCompanionsAndNoopRuns(t *testing.T) {
	tests := []struct {
		name       string
		changed    artifact.Kind
		candidate  artifact.Kind
		wantReload bool
	}{
		{name: "security changed reloads system", changed: artifact.KindSECURITY, candidate: artifact.KindSYSTEM, wantReload: true},
		{name: "system changed reloads security", changed: artifact.KindSYSTEM, candidate: artifact.KindSECURITY, wantReload: true},
		{name: "sam changed reloads system", changed: artifact.KindSAM, candidate: artifact.KindSYSTEM, wantReload: true},
		{name: "system changed reloads sam", changed: artifact.KindSYSTEM, candidate: artifact.KindSAM, wantReload: true},
		{name: "ntds changed reloads system", changed: artifact.KindNTDS, candidate: artifact.KindSYSTEM, wantReload: true},
		{name: "system changed reloads ntds", changed: artifact.KindSYSTEM, candidate: artifact.KindNTDS, wantReload: true},
		{name: "all unchanged does not reload", changed: "", candidate: artifact.KindSYSTEM, wantReload: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := artifactbundle.BundleKey{Host: "host", Share: "share", Scope: "config", Context: "loose"}
			changed := make(map[artifactbundle.BundleKey]map[artifact.Kind]bool)
			if test.changed != "" {
				changed[key] = map[artifact.Kind]bool{test.changed: true}
			}
			candidates := map[artifactbundle.BundleKey]map[artifact.Kind]bundleCandidate{
				key: {test.candidate: {remote: smb.RemoteFile{Path: string(test.candidate)}}},
			}
			got := collectBundleDependencies(changed, candidates, make(map[artifactbundle.BundleKey]map[artifact.Kind]bool))
			if (len(got) != 0) != test.wantReload {
				t.Fatalf("dependencies = %#v, want reload=%v", got, test.wantReload)
			}
		})
	}
}

func TestCollectBundleDependenciesDoesNotReuseMissingPartner(t *testing.T) {
	key := artifactbundle.BundleKey{Host: "host", Share: "share", Scope: "config", Context: "loose"}
	changed := map[artifactbundle.BundleKey]map[artifact.Kind]bool{
		key: {artifact.KindSECURITY: true},
	}
	// The unchanged SYSTEM was present in an earlier run but is not in the
	// current candidate set. A missing dependency must not be synthesized from
	// stale state or produce a bundle re-evaluation.
	got := collectBundleDependencies(changed, map[artifactbundle.BundleKey]map[artifact.Kind]bundleCandidate{}, make(map[artifactbundle.BundleKey]map[artifact.Kind]bool))
	if len(got) != 0 {
		t.Fatalf("dependencies = %#v, want no dependency for unavailable partner", got)
	}
}

type appFakeScanClient struct {
	files          map[string][]byte
	failSystem     bool
	changeSecurity bool
}

func (*appFakeScanClient) SetMaxReadSize(int64)                   {}
func (*appFakeScanClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (*appFakeScanClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (*appFakeScanClient) Close() error { return nil }
func (c *appFakeScanClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	for _, path := range []string{"Windows/System32/config/SECURITY", "Windows/System32/config/SYSTEM"} {
		size := int64(len(c.files[path]))
		modified := time.Unix(100, 0).UTC()
		if c.changeSecurity && path == "Windows/System32/config/SECURITY" {
			size++
			modified = modified.Add(time.Minute)
		}
		if err := fn(smb.RemoteFile{Host: "host", Share: "share", Path: path, Name: path, Size: size, ModifiedAt: modified}); err != nil {
			return err
		}
	}
	return nil
}
func (c *appFakeScanClient) ReadFile(_ string, path string) ([]byte, error) {
	if c.failSystem && path == `Windows\System32\config\SYSTEM` {
		return nil, os.ErrPermission
	}
	return c.files[strings.ReplaceAll(path, `\`, "/")], nil
}

type appCaptureSink struct{ findings []scanner.Finding }

func (s *appCaptureSink) WriteFinding(f scanner.Finding) error {
	s.findings = append(s.findings, f)
	return nil
}
func (*appCaptureSink) Close() error { return nil }

func TestScanHostTransportDependencyFailureDoesNotReuseBundle(t *testing.T) {
	current := uint32(1)
	system := testfixture.Build(testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}})
	// The fixture uses the boot key derived from this SYSTEM class data.
	systemHive, err := registryhive.Open(bytes.NewReader(system), int64(len(system)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	security := testfixture.BuildSecurity(testfixture.SecuritySpec{BootKey: derived.BootKey, LSAKey: [32]byte{2}, Secrets: map[string][]byte{"NL$KM": make([]byte, 32)}})
	files := map[string][]byte{"Windows/System32/config/SECURITY": security, "Windows/System32/config/SYSTEM": system}
	root := t.TempDir()
	inventory, err := state.NewInventoryManager(filepath.Join(root, "inventory.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()
	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	run := func(client *appFakeScanClient, sink scanner.FindingSink) (metrics.Snapshot, error) {
		newScanClientFunc = func() scanClient { return client }
		coordinator := artifactbundle.New(artifactbundle.Options{})
		defer coordinator.Close()
		recorder := metrics.NewCollector()
		engine := scanner.NewEngine(scanner.Options{BundleCoordinator: coordinator, SYSTEMMaxBytes: 64 << 20, SECURITYMaxBytes: 64 << 20, Recorder: recorder}, &rules.Manager{}, sink, logx.New("error"))
		cfg := config.Default()
		cfg.Scan.Username = "user"
		cfg.Scan.Password = "password"
		cfg.Scan.WorkerCount = 1
		err := scanHost(context.Background(), "host", "test", nil, nil, inventory, "ctx-test", "semantics", false, recorder, cfg, engine, sink, logx.New("error"))
		return recorder.Snapshot(), err
	}
	firstSink := &appCaptureSink{}
	_, err = run(&appFakeScanClient{files: files}, firstSink)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstSink.findings) != 1 {
		t.Fatalf("run 1 findings=%d, want one validated bundle", len(firstSink.findings))
	}
	secondSink := &appCaptureSink{}
	second, err := run(&appFakeScanClient{files: files, failSystem: true, changeSecurity: true}, secondSink)
	if err != nil {
		t.Fatal(err)
	}
	if second.Counters.FilesVisited != 1 || second.Counters.FilesRead != 1 || second.Counters.DependencyReloads != 1 {
		t.Fatalf("run 2 counters=%#v, want one ordinary read and one dependency reload", second.Counters)
	}
	if len(secondSink.findings) != 0 {
		t.Fatalf("run 2 findings=%d, want no stale bundle", len(secondSink.findings))
	}
	stats := inventory.Stats()
	if stats.Discovered != 4 || stats.Inspected != 3 || stats.SkippedUnchanged != 1 {
		t.Fatalf("inventory stats=%#v, want cumulative discovered=4 inspected=3 skipped=1", stats)
	}
}

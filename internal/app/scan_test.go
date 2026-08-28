package app

import (
	"testing"

	"snablr/internal/config"
	"snablr/internal/state"
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

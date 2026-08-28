package app

import (
	"strings"
	"testing"

	"snablr/internal/config"
	"snablr/internal/discovery"
)

func TestApplyScanOverridesLeavesWIMConfigUntouchedWhenFlagsUnset(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.WIM.Enabled = false
	cfg.WIM.AutoWIMMaxSize = 64
	cfg.WIM.AllowLargeWIMs = true
	cfg.WIM.MaxWIMSize = 128
	cfg.WIM.MaxMembers = 4
	cfg.WIM.MaxMemberBytes = 256
	cfg.WIM.MaxTotalBytes = 1024

	applyScanOverrides(&cfg, ScanOptions{})

	if cfg.WIM.Enabled {
		t.Fatalf("expected existing wim.enabled to remain false, got %#v", cfg.WIM)
	}
	if cfg.WIM.AutoWIMMaxSize != 64 || !cfg.WIM.AllowLargeWIMs || cfg.WIM.MaxWIMSize != 128 || cfg.WIM.MaxMembers != 4 || cfg.WIM.MaxMemberBytes != 256 || cfg.WIM.MaxTotalBytes != 1024 {
		t.Fatalf("expected WIM config to remain unchanged, got %#v", cfg.WIM)
	}
}

func TestApplyScanOverridesAppliesExplicitWIMCLIOverrides(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	enabled := false
	autoSize := int64(256)
	allowLarge := true
	maxSize := int64(512)
	maxMembers := 16
	maxMemberBytes := int64(2048)
	maxTotalBytes := int64(8192)

	applyScanOverrides(&cfg, ScanOptions{
		WIMEnabled:        &enabled,
		WIMAutoMaxSize:    &autoSize,
		WIMAllowLarge:     &allowLarge,
		WIMMaxSize:        &maxSize,
		WIMMaxMembers:     &maxMembers,
		WIMMaxMemberBytes: &maxMemberBytes,
		WIMMaxTotalBytes:  &maxTotalBytes,
	})

	if cfg.WIM.Enabled != enabled || cfg.WIM.AutoWIMMaxSize != autoSize || cfg.WIM.AllowLargeWIMs != allowLarge || cfg.WIM.MaxWIMSize != maxSize || cfg.WIM.MaxMembers != maxMembers || cfg.WIM.MaxMemberBytes != maxMemberBytes || cfg.WIM.MaxTotalBytes != maxTotalBytes {
		t.Fatalf("expected explicit WIM CLI overrides to apply, got %#v", cfg.WIM)
	}
}

func TestApplyScanOverridesAppliesWIMOverridesAfterProfileSelection(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	enabled := false
	maxSize := int64(536870912)

	applyScanOverrides(&cfg, ScanOptions{
		Profile:    "aggressive",
		WIMEnabled: &enabled,
		WIMMaxSize: &maxSize,
	})

	if cfg.Scan.Profile != "aggressive" {
		t.Fatalf("expected scan profile override to apply, got %q", cfg.Scan.Profile)
	}
	if cfg.WIM.Enabled != enabled || cfg.WIM.MaxWIMSize != maxSize {
		t.Fatalf("expected explicit WIM overrides to win after profile selection, got %#v", cfg.WIM)
	}
}

func TestApplyScanOverridesLeavesWorkerDefaultWhenUnset(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	applyScanOverrides(&cfg, ScanOptions{})

	if cfg.Scan.WorkerCount != 15 {
		t.Fatalf("expected safe default worker count 15, got %d", cfg.Scan.WorkerCount)
	}
}

func TestApplyScanOverridesAppliesExplicitWorkerCount(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	workers := 4
	applyScanOverrides(&cfg, ScanOptions{WorkerCount: &workers})

	if cfg.Scan.WorkerCount != workers {
		t.Fatalf("expected explicit worker count %d, got %d", workers, cfg.Scan.WorkerCount)
	}
}

func TestApplyScanOverridesAppliesExplicitAdaptiveWorkerCount(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	workers := 0
	applyScanOverrides(&cfg, ScanOptions{WorkerCount: &workers})

	if cfg.Scan.WorkerCount != workers {
		t.Fatalf("expected explicit adaptive worker count 0, got %d", cfg.Scan.WorkerCount)
	}
}

func TestApplyScanOverridesAppliesIncrementalStateOptions(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	applyScanOverrides(&cfg, ScanOptions{
		StateDir:    "./state",
		Incremental: true,
		ForceRescan: true,
	})
	if cfg.Scan.StateDir != "./state" || !cfg.Scan.Incremental || !cfg.Scan.ForceRescan {
		t.Fatalf("incremental overrides not applied: %#v", cfg.Scan)
	}
}

func TestValidateScanConfigRequiresIncrementalStateDirectory(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.Incremental = true
	if err := validateScanConfig(cfg); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("expected state directory validation error, got %v", err)
	}
}

func TestValidateScanConfigStateDirectoryEnablesIncrementalUse(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.StateDir = "./state"
	if err := validateScanConfig(cfg); err != nil {
		t.Fatalf("state_dir should enable incremental use: %v", err)
	}
}

func TestValidateScanConfigRejectsInvalidWIMBounds(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.Profile = ""
	cfg.WIM.Enabled = true
	cfg.WIM.AutoWIMMaxSize = 512
	cfg.WIM.MaxWIMSize = 256
	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid WIM size bounds to fail validation")
	}

	cfg = config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.Profile = ""
	cfg.WIM.Enabled = true
	cfg.WIM.AutoWIMMaxSize = 256
	cfg.WIM.MaxWIMSize = 512
	cfg.WIM.MaxMemberBytes = 4096
	cfg.WIM.MaxTotalBytes = 1024
	if err := validateScanConfig(cfg); err == nil {
		t.Fatal("expected invalid WIM extraction byte bounds to fail validation")
	}
}

func TestApplyScanOverridesAppliesLDAPAuthOptions(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	applyScanOverrides(&cfg, ScanOptions{
		AuthMode:       discovery.AuthModeKerberos,
		KerberosCCache: "test.ccache",
		LDAPSPN:        "ldap/DC01.TEST.LOCAL",
	})

	if cfg.Scan.AuthMode != discovery.AuthModeKerberos {
		t.Fatalf("expected auth mode override, got %q", cfg.Scan.AuthMode)
	}
	if cfg.Scan.KerberosCCache != "test.ccache" {
		t.Fatalf("expected kerberos ccache override, got %q", cfg.Scan.KerberosCCache)
	}
	if cfg.Scan.LDAPSPN != "ldap/DC01.TEST.LOCAL" {
		t.Fatalf("expected ldap spn override, got %q", cfg.Scan.LDAPSPN)
	}
}

func TestValidateScanConfigKeepsPasswordModeAsDefault(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.AuthMode = ""
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.Profile = ""

	if err := validateScanConfig(cfg); err != nil {
		t.Fatalf("validateScanConfig returned error: %v", err)
	}
}

func TestValidateScanConfigNTHashMode(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.AuthMode = discovery.AuthModePassword
	cfg.Scan.SMBAuth = "ntlm-hash"
	cfg.Scan.Username = `DOMAIN\user`
	cfg.Scan.Password = ""
	cfg.Scan.NTHash = "0123456789abcdef0123456789abcdef"
	if err := validateScanConfig(cfg); err != nil {
		t.Fatalf("valid NT hash configuration rejected: %v", err)
	}
}

func TestValidateScanConfigRejectsAmbiguousNTHashConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		message string
	}{
		{"missing hash", func(cfg *config.Config) { cfg.Scan.NTHash = "" }, "missing NT hash"},
		{"bad hash", func(cfg *config.Config) { cfg.Scan.NTHash = "not-a-hash" }, "invalid NT hash"},
		{"password with hash", func(cfg *config.Config) { cfg.Scan.Password = "secret" }, "password cannot be supplied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Scan.SMBAuth = "ntlm-hash"
			cfg.Scan.Username = "user"
			cfg.Scan.NTHash = "0123456789abcdef0123456789abcdef"
			tt.mutate(&cfg)
			err := validateScanConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("expected %q error, got %v", tt.message, err)
			}
		})
	}
}

func TestValidateScanConfigRejectsNTHashInPasswordMode(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scan.SMBAuth = "password"
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "secret"
	cfg.Scan.NTHash = "0123456789abcdef0123456789abcdef"
	if err := validateScanConfig(cfg); err == nil || !strings.Contains(err.Error(), "NT hash cannot be supplied") {
		t.Fatalf("expected password/hash conflict, got %v", err)
	}
}

func TestValidateScanConfigRequiresKerberosCCache(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Scan.SMBAuth = "kerberos"
	if err := validateScanConfig(cfg); err == nil || !strings.Contains(err.Error(), "kerberos ccache unavailable") {
		t.Fatalf("expected SMB Kerberos ccache error, got %v", err)
	}
}

func TestResolveSMBSPN(t *testing.T) {
	for _, test := range []struct {
		name     string
		target   string
		hostname string
		override string
		want     string
		wantErr  bool
	}{
		{name: "explicit override", target: "10.0.0.1", override: "cifs/files.example.com", want: "cifs/files.example.com"},
		{name: "hostname", target: "10.0.0.1", hostname: "Files.Example.COM", want: "cifs/files.example.com"},
		{name: "target fqdn", target: "Files.Example.COM", want: "cifs/files.example.com"},
		{name: "ip rejected", target: "10.0.0.1", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSMBSPN(test.target, test.hostname, test.override)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("resolveSMBSPN = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestValidateScanConfigKerberosStillRequiresSMBCredentials(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.AuthMode = discovery.AuthModeKerberos
	cfg.Scan.Username = ""
	cfg.Scan.Password = ""
	cfg.Scan.Profile = ""

	err := validateScanConfig(cfg)
	if err == nil {
		t.Fatal("expected kerberos scan without SMB credentials to fail")
	}
	if !strings.Contains(err.Error(), "missing SMB username") {
		t.Fatalf("expected SMB username error, got %v", err)
	}
}

func TestValidateScanConfigKerberosExplicitTargetsWithoutSMBCredsFailsClearly(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.AuthMode = discovery.AuthModeKerberos
	cfg.Scan.Targets = []string{"FILE01.TEST.LOCAL"}
	cfg.Scan.Username = ""
	cfg.Scan.Password = ""
	cfg.Scan.Profile = ""

	err := validateScanConfig(cfg)
	if err == nil {
		t.Fatal("expected kerberos explicit-target scan without SMB credentials to fail")
	}
	if !strings.Contains(err.Error(), "missing SMB username") {
		t.Fatalf("expected clear SMB username error, got %v", err)
	}
}

func TestValidateScanConfigKerberosExplicitTargetsWithSMBCredsIsAllowed(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Scan.AuthMode = discovery.AuthModeKerberos
	cfg.Scan.Targets = []string{"FILE01.TEST.LOCAL"}
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pass"
	cfg.Scan.Profile = ""

	if err := validateScanConfig(cfg); err != nil {
		t.Fatalf("validateScanConfig returned error: %v", err)
	}
}

func TestValidateDiscoverConfigAllowsKerberosWithoutPassword(t *testing.T) {
	t.Parallel()

	err := validateDiscoverConfig(config.ScanConfig{
		AuthMode: discovery.AuthModeKerberos,
		Domain:   "TEST.LOCAL",
	})
	if err != nil {
		t.Fatalf("validateDiscoverConfig returned error: %v", err)
	}
}

func TestValidateDiscoverConfigRejectsUnsupportedAuthMode(t *testing.T) {
	t.Parallel()

	err := validateDiscoverConfig(config.ScanConfig{
		AuthMode: "invalid",
		Domain:   "TEST.LOCAL",
	})
	if err == nil {
		t.Fatal("expected unsupported auth mode to fail")
	}
}

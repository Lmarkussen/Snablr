package app

import (
	"testing"

	"snablr/internal/config"
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

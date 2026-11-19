package app

import (
	"strings"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/smb"
)

// PasswordPrompt reads the authentication password interactively.
type PasswordPrompt func() (string, error)

// scanNeedsPassword reports whether SMB authentication needs a password that
// neither the CLI nor the config file supplied. NT-hash and Kerberos SMB
// authentication never use a password, and validation rejects one, so they
// must not trigger a prompt.
func scanNeedsPassword(scanCfg config.ScanConfig) bool {
	if scanCfg.Password != "" || strings.TrimSpace(scanCfg.Username) == "" {
		return false
	}
	smbAuthMode := strings.ToLower(strings.TrimSpace(scanCfg.SMBAuth))
	if smbAuthMode == "" {
		smbAuthMode = string(smb.AuthModePassword)
	}
	return smbAuthMode == string(smb.AuthModePassword)
}

// discoverNeedsPassword reports whether LDAP discovery will authenticate with
// a password that neither the CLI nor the config file supplied.
func discoverNeedsPassword(scanCfg config.ScanConfig) bool {
	if scanCfg.Password != "" || strings.TrimSpace(scanCfg.Username) == "" {
		return false
	}
	if normalizeLDAPAuthMode(scanCfg.AuthMode) != discovery.AuthModePassword {
		return false
	}
	return (!scanCfg.NoLDAP && len(scanCfg.Targets) == 0 && strings.TrimSpace(scanCfg.TargetsFile) == "") || scanCfg.DiscoverDFS
}

// promptForMissingPassword prompts once the effective configuration (CLI and
// config file merged) shows that a password is needed and missing.
func promptForMissingPassword(cfg *config.Config, prompt PasswordPrompt, needed func(config.ScanConfig) bool) error {
	if prompt == nil || !needed(cfg.Scan) {
		return nil
	}
	password, err := prompt()
	if err != nil {
		return err
	}
	cfg.Scan.Password = password
	return nil
}

package app

import (
	"errors"
	"testing"

	"snablr/internal/config"
)

// The automatic password prompt must follow the merged CLI and config
// settings. NT-hash and Kerberos SMB authentication reject a password, so
// prompting for one there produced an unusable password or failed without a
// terminal.
func TestScanPromptsOnlyWhenSMBPasswordIsNeededAndMissing(t *testing.T) {
	cases := []struct {
		name string
		scan config.ScanConfig
		want bool
	}{
		{"password auth without password", config.ScanConfig{Username: "svc_synthetic"}, true},
		{"explicit password auth", config.ScanConfig{Username: "svc_synthetic", SMBAuth: "password"}, true},
		{"password from config", config.ScanConfig{Username: "svc_synthetic", Password: "Synthetic-Config-1!"}, false},
		{"ntlm-hash auth", config.ScanConfig{Username: "svc_synthetic", SMBAuth: "ntlm-hash", NTHash: "00112233445566778899aabbccddeeff"}, false},
		{"ntlm-hash auth from config casing", config.ScanConfig{Username: "svc_synthetic", SMBAuth: " NTLM-Hash "}, false},
		{"kerberos auth", config.ScanConfig{Username: "svc_synthetic", SMBAuth: "kerberos"}, false},
		{"no username", config.ScanConfig{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{Scan: tc.scan}
			prompted := false
			err := promptForMissingPassword(&cfg, func() (string, error) {
				prompted = true
				return "Synthetic-Prompted-2!", nil
			}, scanNeedsPassword)
			if err != nil {
				t.Fatal(err)
			}
			if prompted != tc.want {
				t.Fatalf("prompted=%v, want %v", prompted, tc.want)
			}
			if prompted && cfg.Scan.Password != "Synthetic-Prompted-2!" {
				t.Fatal("prompted password was not applied")
			}
		})
	}
}

func TestDiscoverPromptsOnlyWhenLDAPPasswordIsNeeded(t *testing.T) {
	cases := []struct {
		name string
		scan config.ScanConfig
		want bool
	}{
		{"ldap discovery with password auth", config.ScanConfig{Username: "svc_synthetic"}, true},
		{"explicit targets need no ldap", config.ScanConfig{Username: "svc_synthetic", Targets: []string{"fileserver.example.test"}}, false},
		{"dfs discovery still needs ldap", config.ScanConfig{Username: "svc_synthetic", Targets: []string{"fileserver.example.test"}, DiscoverDFS: true}, true},
		{"kerberos ldap", config.ScanConfig{Username: "svc_synthetic", AuthMode: "kerberos"}, false},
		{"password from config", config.ScanConfig{Username: "svc_synthetic", Password: "Synthetic-Config-1!"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoverNeedsPassword(tc.scan); got != tc.want {
				t.Fatalf("discoverNeedsPassword=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestPromptErrorsAreReturnedAndNilPromptIsSkipped(t *testing.T) {
	cfg := config.Config{Scan: config.ScanConfig{Username: "svc_synthetic"}}
	if err := promptForMissingPassword(&cfg, nil, scanNeedsPassword); err != nil {
		t.Fatalf("nil prompt returned %v", err)
	}
	want := errors.New("password input requires an interactive terminal")
	if err := promptForMissingPassword(&cfg, func() (string, error) { return "", want }, scanNeedsPassword); !errors.Is(err, want) {
		t.Fatalf("prompt error not returned: %v", err)
	}
}

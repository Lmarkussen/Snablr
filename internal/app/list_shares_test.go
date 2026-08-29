package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

type fakeListSharesClient struct {
	auth       smb.Auth
	shares     []smb.ShareInfo
	connectErr error
	listErr    error
}

func (f *fakeListSharesClient) ConnectWithAuth(_ string, auth smb.Auth) error {
	f.auth = auth
	return f.connectErr
}

func (f *fakeListSharesClient) ListAccessibleShares(context.Context) ([]smb.ShareInfo, error) {
	return f.shares, f.listErr
}

func (f *fakeListSharesClient) Close() error { return nil }

func TestRunListSharesUsesAuthAndDoesNotCreateScanState(t *testing.T) {
	originalResolve := resolveTargetsFunc
	originalClient := newListSharesClient
	originalPreflight := runScanPreflightFunc
	t.Cleanup(func() {
		resolveTargetsFunc = originalResolve
		newListSharesClient = originalClient
		runScanPreflightFunc = originalPreflight
	})

	resolveTargetsFunc = func(context.Context, config.ScanConfig, discovery.Logger, metrics.Recorder) (discovery.PipelineResult, error) {
		return discovery.PipelineResult{ReachableTargets: []discovery.Target{{Hostname: "server-a"}}}, nil
	}
	runScanPreflightFunc = func(context.Context, config.Config, bool, *logx.Logger) error { return nil }
	fake := &fakeListSharesClient{shares: []smb.ShareInfo{{Name: "Public"}}}
	newListSharesClient = func() listSharesClient { return fake }
	cfg := config.Default()
	cfg.Scan.SMBAuth = "password"
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "pw"
	if err := runListShares(context.Background(), cfg, logx.New("error")); err != nil {
		t.Fatal(err)
	}
	if fake.auth.Mode != smb.AuthModePassword || fake.auth.Password != "pw" {
		t.Fatalf("unexpected auth passed to list client: mode=%q password-set=%v", fake.auth.Mode, fake.auth.Password != "")
	}
}

func TestSmbAuthForHostSupportsAllModes(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.ScanConfig
		mode smb.AuthMode
	}{
		{name: "password", cfg: config.ScanConfig{SMBAuth: "password", Username: "user", Password: "pw"}, mode: smb.AuthModePassword},
		{name: "ntlm", cfg: config.ScanConfig{SMBAuth: "ntlm-hash", Username: "user", NTHash: "0123456789abcdef0123456789abcdef"}, mode: smb.AuthModeNTHash},
		{name: "kerberos", cfg: config.ScanConfig{SMBAuth: "kerberos", Username: "user", SMBHostname: "server.example.test"}, mode: smb.AuthModeKerberos},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := smbAuthForHost("server.example.test", tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if auth.Mode != tt.mode {
				t.Fatalf("mode=%q, want %q", auth.Mode, tt.mode)
			}
			if (auth.Mode == smb.AuthModeNTHash || auth.Mode == smb.AuthModeKerberos) && auth.Password != "" {
				t.Fatalf("unexpected auth secret fields: mode=%q", auth.Mode)
			}
		})
	}
}

func TestWriteListSharesOutputSingleTargetIncludesIdentityUNCAndCount(t *testing.T) {
	var output bytes.Buffer
	err := writeListSharesOutput(&output, `DOMAIN\alice`, []listSharesResult{{
		targetLabel: "fileserver.example.test (10.0.0.10)",
		uncHost:     "fileserver.example.test",
		shares:      []smb.ShareInfo{{Name: "Finance"}, {Name: "Projects"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		`Readable shares for DOMAIN\alice on fileserver.example.test (10.0.0.10):`,
		`\\fileserver.example.test\Finance`,
		`\\fileserver.example.test\Projects`,
		"2 readable shares found.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"password", "nt_hash", "ccache", "ticket"} {
		if strings.Contains(strings.ToLower(text), secret) {
			t.Fatalf("output contains credential material marker %q", secret)
		}
	}
}

func TestWriteListSharesOutputIPOnlyMultipleTargetsAndZeroResult(t *testing.T) {
	var output bytes.Buffer
	err := writeListSharesOutput(&output, "alice", []listSharesResult{
		{targetLabel: "10.0.0.20", uncHost: "10.0.0.20", shares: nil},
		{targetLabel: "server.example.test (10.0.0.10)", uncHost: "server.example.test", shares: []smb.ShareInfo{{Name: "Public"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"Readable shares for alice on 10.0.0.20:",
		"  None.",
		"0 readable shares found.",
		"Readable shares for alice on server.example.test (10.0.0.10):",
		`\\server.example.test\Public`,
		"1 readable share found.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestListSharesIdentityAndTargetFormatting(t *testing.T) {
	if got := listSharesIdentity(config.ScanConfig{Username: "alice", Domain: "DOMAIN"}); got != `DOMAIN\alice` {
		t.Fatalf("identity = %q", got)
	}
	if got := listSharesIdentity(config.ScanConfig{Username: `DOMAIN\alice`, Domain: "OTHER"}); got != `DOMAIN\alice` {
		t.Fatalf("qualified identity = %q", got)
	}
	if got := listSharesTargetLabel(discovery.Target{Hostname: "server.example.test", IP: "10.0.0.10"}); got != "server.example.test (10.0.0.10)" {
		t.Fatalf("target label = %q", got)
	}
	if got := listSharesTargetLabel(discovery.Target{IP: "10.0.0.20"}); got != "10.0.0.20" {
		t.Fatalf("IP target label = %q", got)
	}
	if got := listSharesTargetLabel(discovery.Target{Hostname: "server.example.test"}); got != "server.example.test" {
		t.Fatalf("hostname target label = %q", got)
	}
}

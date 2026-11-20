package app

import (
	"context"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/planner"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// The share layout of a Configuration Manager site server.
var siteServerSharePaths = map[string]string{
	"admin$":           `C:\Windows`,
	"c$":               `C:\`,
	"easysetuppayload": `C:\Program Files\Microsoft Configuration Manager\EasySetupPayload`,
	"reminst":          `C:\RemoteInstall`,
	"software_dist":    `C:\software_dist`,
	"sms_ps1":          `C:\Program Files\Microsoft Configuration Manager`,
}

func TestNestedShareFoldersFollowScannedShares(t *testing.T) {
	plan := func(names ...string) []planner.PlannedTarget {
		var out []planner.PlannedTarget
		for _, name := range names {
			out = append(out, planner.PlannedTarget{Host: "site", Share: name})
		}
		return out
	}
	got := nestedShareFolders(plan("C$", "EasySetupPayload", "REMINST", "software_dist", "SMS_PS1"), siteServerSharePaths)
	want := map[string][]nestedShare{
		"c$": {
			{Folder: "Program Files/Microsoft Configuration Manager", Share: "SMS_PS1"},
			{Folder: "Program Files/Microsoft Configuration Manager/EasySetupPayload", Share: "EasySetupPayload"},
			{Folder: "RemoteInstall", Share: "REMINST"},
			{Folder: "software_dist", Share: "software_dist"},
		},
		"sms_ps1": {{Folder: "EasySetupPayload", Share: "EasySetupPayload"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nested folders=%+v", got)
	}
	// ADMIN$ is not scanned, so C$ keeps its Windows folder.
	if got := nestedShareFolders(plan("C$"), siteServerSharePaths); len(got) != 0 {
		t.Fatalf("unscanned shares took folders: %+v", got)
	}
	if got := nestedShareFolders(plan("C$", "software_dist"), nil); got != nil {
		t.Fatalf("without share paths: %+v", got)
	}
}

// aliasClient is an administrative session on a server where software_dist is a
// folder of C$.
type aliasClient struct {
	mu       sync.Mutex
	excludes map[string][]string
}

func (*aliasClient) SetMaxReadSize(int64)                               {}
func (*aliasClient) SetOperationContext(context.Context, time.Duration) {}
func (*aliasClient) Close() error                                       { return nil }
func (*aliasClient) ConnectWithAuth(string, smb.Auth) error             { return nil }
func (*aliasClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "C$"}, {Name: "software_dist"}}, nil
}
func (*aliasClient) SharePaths() (map[string]string, error) {
	return map[string]string{"c$": `C:\`, "software_dist": `C:\software_dist`}, nil
}
func (c *aliasClient) WalkShareWithOptions(share string, opts smb.WalkOptions, _ func(smb.RemoteFile) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.excludes[share] = append([]string{}, opts.ExcludePaths...)
	return nil
}
func (*aliasClient) ReadFilePrefix(string, string, int64) ([]byte, error) { return nil, nil }
func (*aliasClient) ReadFile(string, string) ([]byte, error)              { return nil, nil }

func TestScanHostWalksAliasedFolderOnceAsItsShare(t *testing.T) {
	client := &aliasClient{excludes: map[string][]string{}}
	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	cfg := config.Default()
	cfg.Scan.Username, cfg.Scan.Password = "user", "password"
	cfg.Scan.ExcludePath = []string{"Temp"}
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sink := &appCaptureSink{}
	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{Recorder: recorder, MaxFileSizeBytes: cfg.Scan.MaxFileSize, MaxReadBytes: scanReadLimit(cfg)}, manager, sink, logx.New("error"))
	if err := scanHost(context.Background(), "site.example.test", "test", nil, nil, nil, "ctx", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error")); err != nil {
		t.Fatalf("scanHost: %v", err)
	}
	if got := client.excludes["C$"]; !reflect.DeepEqual(got, []string{"Temp", "software_dist"}) {
		t.Fatalf("C$ walk excludes %v, want the configured exclusion and software_dist", got)
	}
	if got := client.excludes["software_dist"]; !reflect.DeepEqual(got, []string{"Temp"}) {
		t.Fatalf("software_dist walk excludes %v", got)
	}
}

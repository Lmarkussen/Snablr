package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// loneHiveClient serves a SAM hive without its SYSTEM partner on the first
// host walked and records the temporary artifacts present when the next host
// is walked.
type loneHiveClient struct {
	shared *loneHiveState
}

type loneHiveState struct {
	mu               sync.Mutex
	walks            int
	tmpDir           string
	leftOnSecondHost []string
}

func (*loneHiveClient) SetMaxReadSize(int64)                               {}
func (*loneHiveClient) SetOperationContext(context.Context, time.Duration) {}
func (*loneHiveClient) Close() error                                       { return nil }
func (*loneHiveClient) ConnectWithAuth(string, smb.Auth) error             { return nil }
func (*loneHiveClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *loneHiveClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	c.shared.mu.Lock()
	c.shared.walks++
	walk := c.shared.walks
	c.shared.mu.Unlock()
	if walk == 1 {
		return fn(smb.RemoteFile{Host: "first", Share: "share", Path: "Windows/System32/config/SAM", Name: "SAM", Size: 64, ModifiedAt: time.Unix(1000, 0).UTC()})
	}
	entries, err := os.ReadDir(c.shared.tmpDir)
	if err != nil {
		return err
	}
	c.shared.mu.Lock()
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "artifact-") {
			c.shared.leftOnSecondHost = append(c.shared.leftOnSecondHost, entry.Name())
		}
	}
	c.shared.mu.Unlock()
	return nil
}
func (c *loneHiveClient) ReadFilePrefix(share, path string, _ int64) ([]byte, error) {
	return c.ReadFile(share, path)
}
func (*loneHiveClient) ReadFile(string, string) ([]byte, error) {
	return []byte(strings.Repeat("SYNTHETIC SAM HIVE ", 4)), nil
}

// A SAM, SECURITY or NTDS artifact whose SYSTEM partner never appears is kept
// for its bundle; it must be released once its host is done, not kept on disk
// for the rest of the scan.
func TestRunScanReleasesIncompleteBundlesAfterEachHost(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	origPreflight, origWriter, origResolve, origClient := runScanPreflightFunc, newOutputWriterFunc, resolveTargetsFunc, newScanClientFunc
	defer func() {
		runScanPreflightFunc, newOutputWriterFunc, resolveTargetsFunc, newScanClientFunc = origPreflight, origWriter, origResolve, origClient
	}()
	state := &loneHiveState{tmpDir: tmp}
	runScanPreflightFunc = func(context.Context, config.Config, bool, *logx.Logger) error { return nil }
	resolveTargetsFunc = func(context.Context, config.ScanConfig, discovery.Logger, metrics.Recorder) (discovery.PipelineResult, error) {
		targets := []discovery.Target{
			{Input: "first.example.test", Hostname: "first.example.test", Reachable445: true, Source: "test"},
			{Input: "second.example.test", Hostname: "second.example.test", Reachable445: true, Source: "test"},
		}
		return discovery.PipelineResult{AllTargets: targets, ReachableTargets: targets}, nil
	}
	newOutputWriterFunc = func(config.OutputConfig) (scanner.FindingSink, error) { return noopSink{}, nil }
	newScanClientFunc = func() scanClient { return &loneHiveClient{shared: state} }

	out := t.TempDir()
	err := RunScan(context.Background(), ScanOptions{
		Username:          "user",
		Password:          "pass",
		Targets:           []string{"first.example.test", "second.example.test"},
		NoTUI:             true,
		SQLiteStateFile:   filepath.Join(out, "flush.db"),
		ScannedTargetsOut: filepath.Join(out, "scanned_targets.txt"),
	})
	// A hive without its partner leaves the first host's coverage incomplete.
	if err != nil && !strings.Contains(err.Error(), "scan coverage incomplete") {
		t.Fatalf("RunScan: %v", err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.walks != 2 {
		t.Fatalf("walked %d hosts, want 2", state.walks)
	}
	if len(state.leftOnSecondHost) > 0 {
		t.Fatalf("artifacts of the first host still on disk while the next host was scanned: %v", state.leftOnSecondHost)
	}
	entries, _ := os.ReadDir(tmp)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "artifact-") || strings.HasPrefix(entry.Name(), "snablr-sqlite-") {
			t.Errorf("left behind after the scan: %s", entry.Name())
		}
	}
}

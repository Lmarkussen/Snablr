package app

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// cancelOnCloseSink stands in for the live TUI, which stays open after the
// scan and is closed by a signal: closing it cancels the scan context.
type cancelOnCloseSink struct{ cancel context.CancelFunc }

func (*cancelOnCloseSink) WriteFinding(scanner.Finding) error { return nil }
func (s *cancelOnCloseSink) Close() error {
	s.cancel()
	return nil
}

type emptyShareClient struct{}

func (emptyShareClient) SetMaxReadSize(int64)                               {}
func (emptyShareClient) SetOperationContext(context.Context, time.Duration) {}
func (emptyShareClient) Close() error                                       { return nil }
func (emptyShareClient) ConnectWithAuth(string, smb.Auth) error             { return nil }
func (emptyShareClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (emptyShareClient) WalkShareWithOptions(string, smb.WalkOptions, func(smb.RemoteFile) error) error {
	return nil
}
func (emptyShareClient) ReadFilePrefix(string, string, int64) ([]byte, error) { return nil, nil }
func (emptyShareClient) ReadFile(string, string) ([]byte, error)              { return nil, nil }

// A scan that finished is recorded as completed even when the signal that
// closes its still-open output arrives afterwards.
func TestSignalAfterFinishedScanKeepsCompletedStatus(t *testing.T) {
	origPreflight, origWriter, origResolve, origClient := runScanPreflightFunc, newOutputWriterFunc, resolveTargetsFunc, newScanClientFunc
	defer func() {
		runScanPreflightFunc, newOutputWriterFunc, resolveTargetsFunc, newScanClientFunc = origPreflight, origWriter, origResolve, origClient
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runScanPreflightFunc = func(context.Context, config.Config, bool, *logx.Logger) error { return nil }
	resolveTargetsFunc = func(context.Context, config.ScanConfig, discovery.Logger, metrics.Recorder) (discovery.PipelineResult, error) {
		targets := []discovery.Target{{Input: "fileserver.example.test", Hostname: "fileserver.example.test", Reachable445: true, Source: "test"}}
		return discovery.PipelineResult{AllTargets: targets, ReachableTargets: targets}, nil
	}
	newOutputWriterFunc = func(config.OutputConfig) (scanner.FindingSink, error) { return &cancelOnCloseSink{cancel: cancel}, nil }
	newScanClientFunc = func() scanClient { return emptyShareClient{} }

	out := t.TempDir()
	dbPath := filepath.Join(out, "status.db")
	err := RunScan(ctx, ScanOptions{
		Username: "user", Password: "pass", Targets: []string{"fileserver.example.test"}, NoTUI: true, NoOutfile: true,
		SQLiteStateFile: dbPath, ScannedTargetsOut: filepath.Join(out, "scanned_targets.txt"),
	})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status string
	if err := db.QueryRow(`SELECT status FROM scans`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("status=%q, want completed", status)
	}
}

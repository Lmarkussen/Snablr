package app

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// withheldShareScanClient models a target whose walk is parked on a withheld
// share: the legacy entry point never returns, and only the context-aware entry
// point can be released by cancellation. A scan that keeps using the legacy
// entry point therefore cannot be interrupted while a share is withheld.
type withheldShareScanClient struct {
	walkStarted chan struct{}
	legacyUsed  atomic.Bool
	contextUsed atomic.Bool
}

func newWithheldShareScanClient() *withheldShareScanClient {
	return &withheldShareScanClient{walkStarted: make(chan struct{})}
}

func (c *withheldShareScanClient) SetMaxReadSize(int64)                   {}
func (c *withheldShareScanClient) Close() error                           { return nil }
func (c *withheldShareScanClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (c *withheldShareScanClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share-a"}}, nil
}
func (c *withheldShareScanClient) ReadFile(string, string) ([]byte, error) { return nil, nil }

// WalkShareWithOptions is the pre-existing, context-free entry point. A
// containment wait reached through it ignores the scan's cancellation.
func (c *withheldShareScanClient) WalkShareWithOptions(string, smb.WalkOptions, func(smb.RemoteFile) error) error {
	c.legacyUsed.Store(true)
	close(c.walkStarted)
	select {}
}

func (c *withheldShareScanClient) WalkShareWithOptionsContext(ctx context.Context, _ string, _ smb.WalkOptions, _ func(smb.RemoteFile) error) error {
	c.contextUsed.Store(true)
	close(c.walkStarted)
	<-ctx.Done()
	return ctx.Err()
}

// TestScanHostCancellationReleasesWalkerWaitingOnWithheldShare is the operator
// cancellation acceptance test: a target parked on a withheld share must exit
// promptly when the scan context is cancelled (Ctrl-C / --max-scan-time), which
// requires the walk to run under the caller's context.
func TestScanHostCancellationReleasesWalkerWaitingOnWithheldShare(t *testing.T) {
	client := newWithheldShareScanClient()

	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1

	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{Recorder: recorder}, &rules.Manager{}, nil, logx.New("error"))
	sink := &recoverySink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- scanHost(ctx, "host", "test", nil, nil, nil, "ctx-cancel", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error"))
	}()

	select {
	case <-client.walkStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("scan never reached the share walk")
	}
	if client.legacyUsed.Load() {
		t.Fatal("scan used the context-free walk entry point while a share was withheld")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("cancelled scan took %s to exit", elapsed)
		}
		if err == nil {
			t.Fatal("cancelled scan reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled scan did not exit: the walk is parked on a withheld share and ignores cancellation")
	}
	if !client.contextUsed.Load() {
		t.Fatal("scan did not use the context-aware walk entry point")
	}
}

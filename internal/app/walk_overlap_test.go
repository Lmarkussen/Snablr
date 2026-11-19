package app

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// slowWalkClient walks a share whose listing is slow: after the first file it
// waits for that file to be read before listing more. A scanner that only
// reads once the walk ends never reads during the walk.
type slowWalkClient struct {
	mu          sync.Mutex
	readStarted chan struct{}
	readDuring  bool
}

func (*slowWalkClient) SetMaxReadSize(int64)                               {}
func (*slowWalkClient) SetOperationContext(context.Context, time.Duration) {}
func (*slowWalkClient) Close() error                                       { return nil }
func (*slowWalkClient) ConnectWithAuth(string, smb.Auth) error             { return nil }
func (*slowWalkClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *slowWalkClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	emit := func(name string) error {
		return fn(smb.RemoteFile{Host: "fileserver.example.test", Share: "share", Path: name, Name: name, Extension: ".txt", Size: 32, ModifiedAt: time.Unix(1000, 0).UTC()})
	}
	if err := emit("first.txt"); err != nil {
		return err
	}
	// The next directory listing is slow; files already listed should be
	// read meanwhile. Entries keep arriving while the listing is under way.
	deadline := time.After(5 * time.Second)
	for index := 0; ; index++ {
		select {
		case <-c.readStarted:
			c.mu.Lock()
			c.readDuring = true
			c.mu.Unlock()
			return emit("last.txt")
		case <-deadline:
			return emit("last.txt")
		case <-time.After(20 * time.Millisecond):
			if err := fn(smb.RemoteFile{Host: "fileserver.example.test", Share: "share", Path: "dir", Name: "dir", IsDir: true}); err != nil {
				return err
			}
		}
	}
}
func (c *slowWalkClient) ReadFilePrefix(share, path string, _ int64) ([]byte, error) {
	return c.ReadFile(share, path)
}
func (c *slowWalkClient) ReadFile(string, string) ([]byte, error) {
	c.mu.Lock()
	select {
	case <-c.readStarted:
	default:
		close(c.readStarted)
	}
	c.mu.Unlock()
	return []byte("synthetic harmless content\n"), nil
}

func TestScanHostReadsWhileShareIsStillWalked(t *testing.T) {
	oldInterval := sharePlanningFlushInterval
	sharePlanningFlushInterval = 50 * time.Millisecond
	defer func() { sharePlanningFlushInterval = oldInterval }()

	client := &slowWalkClient{readStarted: make(chan struct{})}
	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	sink := &appCaptureSink{}
	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{Recorder: recorder, MaxFileSizeBytes: cfg.Scan.MaxFileSize, MaxReadBytes: scanReadLimit(cfg)}, manager, sink, logx.New("error"))
	if err := scanHost(context.Background(), "fileserver.example.test", "test", nil, nil, nil, "ctx", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error")); err != nil {
		t.Fatalf("scanHost: %v", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.readDuring {
		t.Fatal("no file was read while the share was still being walked")
	}
	if got := recorder.Snapshot().Counters.FilesRead; got != 2 {
		t.Fatalf("files read=%d, want both files", got)
	}
}

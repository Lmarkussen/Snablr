package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/state"
	"snablr/pkg/logx"

	"github.com/hirochachacha/go-smb2"
)

// recoveryScanClient is a scripted transport for scan-level recovery tests.
type recoveryScanClient struct {
	files      map[string][]byte
	failReads  map[string]error
	readCounts map[string]int
	stats      smb.TransportStats
}

func newRecoveryScanClient(files map[string][]byte, failing map[string]error) *recoveryScanClient {
	return &recoveryScanClient{files: files, failReads: failing, readCounts: map[string]int{}}
}

// recoverySink records read-error observations so coverage accounting can be
// asserted at the scan level.
type recoverySink struct {
	findings   []scanner.Finding
	readErrors int
}

func (s *recoverySink) WriteFinding(f scanner.Finding) error {
	s.findings = append(s.findings, f)
	return nil
}
func (*recoverySink) Close() error                            { return nil }
func (*recoverySink) RecordHost(string)                       {}
func (*recoverySink) RecordShare(string, string)              {}
func (*recoverySink) RecordFile(scanner.FileMetadata)         {}
func (*recoverySink) RecordSkip(scanner.FileMetadata, string) {}
func (s *recoverySink) RecordReadError(scanner.FileMetadata, error) {
	s.readErrors++
}

func (*recoveryScanClient) SetMaxReadSize(int64)                   {}
func (*recoveryScanClient) Close() error                           { return nil }
func (*recoveryScanClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (*recoveryScanClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *recoveryScanClient) TransportStats() smb.TransportStats { return c.stats }
func (c *recoveryScanClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	paths := make([]string, 0, len(c.files))
	for path := range c.files {
		paths = append(paths, path)
	}
	// Deterministic order so the recovery accounting is reproducible.
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j] < paths[i] {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
	for _, path := range paths {
		if err := fn(smb.RemoteFile{
			Host: "host", Share: "share", Path: path, Name: path,
			Size: int64(len(c.files[path])), ModifiedAt: time.Unix(1000, 0).UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
func (c *recoveryScanClient) ReadFile(_ string, path string) ([]byte, error) {
	normalized := strings.ReplaceAll(path, `\`, "/")
	c.readCounts[normalized]++
	if err := c.failReads[normalized]; err != nil {
		return nil, err
	}
	return c.files[normalized], nil
}

// TestScanTransportFailureIsRetryableAndNotCompleted is A12/A17 case 10: a file
// whose read failed after the retry budget must not be recorded as completed,
// and a later healthy run must inspect it.
func TestScanTransportFailureIsRetryableAndNotCompleted(t *testing.T) {
	files := map[string][]byte{
		"A.txt":  []byte("alpha"),
		"B.docx": []byte("bravo"),
		"C.xlsx": []byte("charlie"),
		"D.txt":  []byte("delta"),
	}
	root := t.TempDir()
	inventory, err := state.NewInventoryManager(filepath.Join(root, "inventory.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()

	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()

	run := func(client *recoveryScanClient) (metrics.Snapshot, *recoverySink, error) {
		newScanClientFunc = func() scanClient { return client }
		recorder := metrics.NewCollector()
		engine := scanner.NewEngine(scanner.Options{Recorder: recorder}, &rules.Manager{}, nil, logx.New("error"))
		cfg := config.Default()
		cfg.Scan.Username = "user"
		cfg.Scan.Password = "password"
		cfg.Scan.WorkerCount = 1
		sink := &recoverySink{}
		err := scanHost(context.Background(), "host", "test", nil, nil, inventory, "ctx-test", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error"))
		return recorder.Snapshot(), sink, err
	}

	// RUN 1: B's read fails with a transport error after retries.
	first := newRecoveryScanClient(files, map[string]error{"B.docx": &smb2.TransportError{Err: syscall.ECONNRESET}})
	first.stats = smb.TransportStats{TransportFailures: 1, ReconnectsAttempted: 2, ReconnectsFailed: 2, RetryExhausted: 1}
	snapshot, _, err := run(first)
	if err != nil {
		t.Fatalf("run 1 returned error: %v", err)
	}
	if snapshot.Counters.SMBRetryExhausted != 1 || snapshot.Counters.SMBReconnectsFailed != 2 {
		t.Fatalf("transport recovery was not accounted: %#v", snapshot.Counters)
	}

	// B must still be eligible for inspection (not completed).
	decision, err := inventory.Prepare(state.FileObservation{
		Server: "host", Share: "share", Path: "B.docx",
		Size: int64(len(files["B.docx"])), ModifiedAt: time.Unix(1000, 0).UTC(),
	}, "ctx-test", "semantics", false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatalf("file failed after retry exhaustion was marked completed: %s", decision.Reason)
	}

	// RUN 2: transport is healthy again; B must be re-read.
	second := newRecoveryScanClient(files, nil)
	if _, _, err := run(second); err != nil {
		t.Fatalf("run 2 returned error: %v", err)
	}
	if second.readCounts["B.docx"] == 0 {
		t.Fatalf("B was not re-inspected on the healthy run: %#v", second.readCounts)
	}
	// Files that completed successfully in run 1 stay skipped (incremental
	// reuse), while the retryable failure is the only one re-read.
	if second.readCounts["A.txt"] != 0 || second.readCounts["D.txt"] != 0 {
		t.Fatalf("completed files were re-read instead of reused: %#v", second.readCounts)
	}

	raw, err := os.ReadFile(inventory.Path())
	if err != nil {
		// The manager persists on save/close; flush before inspecting state.
		if saveErr := inventory.Save(); saveErr != nil {
			t.Fatalf("save inventory: %v", saveErr)
		}
		raw, err = os.ReadFile(inventory.Path())
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alpha", "bravo", "charlie", "delta"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("incremental state persisted file content")
		}
	}
}

// TestScanReportsCoverageIncompleteWhenReadsFail is A15: a scan with failed
// reads must be distinguishable from a complete one at the metrics level.
func TestScanReportsCoverageIncompleteWhenReadsFail(t *testing.T) {
	files := map[string][]byte{"A.txt": []byte("alpha"), "B.docx": []byte("bravo")}
	inventory, err := state.NewInventoryManager(filepath.Join(t.TempDir(), "inventory.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()
	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()

	client := newRecoveryScanClient(files, map[string]error{"B.docx": errors.New("read failed after reconnect retries")})
	client.stats = smb.TransportStats{TransportFailures: 3, ReconnectsAttempted: 2, ReconnectsSucceeded: 1, OperationsRetried: 2, FilesRecovered: 1, RetryExhausted: 1, EnumerationFailures: 1}
	newScanClientFunc = func() scanClient { return client }

	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{Recorder: recorder}, &rules.Manager{}, nil, logx.New("error"))
	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1
	sink := &recoverySink{}
	if err := scanHost(context.Background(), "host", "test", nil, nil, inventory, "ctx-test", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error")); err != nil {
		t.Fatalf("scanHost returned error: %v", err)
	}
	// The read failure is recorded as an observer read error (coverage input).
	if sink.readErrors == 0 {
		t.Fatalf("expected the failed read to be recorded")
	}
	counters := recorder.Snapshot().Counters
	if counters.SMBTransportFailures != 3 || counters.SMBReconnectsAttempted != 2 || counters.SMBReconnectsSucceeded != 1 ||
		counters.SMBOperationsRetried != 2 || counters.SMBFilesRecovered != 1 || counters.SMBRetryExhausted != 1 || counters.SMBEnumerationFailures != 1 {
		t.Fatalf("transport counters were not propagated to the run metrics: %#v", counters)
	}
}

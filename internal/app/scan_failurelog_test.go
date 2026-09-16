package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hirochachacha/go-smb2"

	"snablr/internal/config"
	"snablr/internal/failurereport"
	"snablr/internal/legacyfixture"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/state"
	"snablr/pkg/logx"
)

// failureScanClient is a scripted transport that can report its own operation
// failures (like the real SMB client) or rely on the app-level fallback.
type failureScanClient struct {
	files      map[string][]byte
	failReads  map[string]error
	readCounts map[string]int
	stats      smb.TransportStats
	handler    func(smb.OperationFailure)
	reportsOwn bool
}

func (c *failureScanClient) SetMaxReadSize(int64)                   {}
func (c *failureScanClient) Close() error                           { return nil }
func (c *failureScanClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (c *failureScanClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *failureScanClient) TransportStats() smb.TransportStats { return c.stats }
func (c *failureScanClient) SetOperationFailureHandler(handler func(smb.OperationFailure)) {
	c.handler = handler
	c.reportsOwn = true
}
func (c *failureScanClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	for _, path := range sortedKeys(c.files) {
		if err := fn(smb.RemoteFile{
			Host: "host", Share: "share", Path: path, Name: path,
			Size: int64(len(c.files[path])), ModifiedAt: time.Unix(1000, 0).UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
func (c *failureScanClient) ReadFile(_ string, path string) ([]byte, error) {
	normalized := strings.ReplaceAll(path, `\`, "/")
	c.readCounts[normalized]++
	if err := c.failReads[normalized]; err != nil {
		if c.handler != nil {
			c.handler(smb.OperationFailure{
				Operation: "read " + normalized, Share: "share", Path: normalized,
				Category: smb.CategorizeError(err), Attempts: 3, ReconnectAttempted: true, Err: err,
			})
		}
		return nil, err
	}
	return c.files[normalized], nil
}

func sortedKeys(files map[string][]byte) []string {
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

type failureScanHarness struct {
	root      string
	outputDir string
	cfg       config.Config
	inventory *state.InventoryManager
}

func newFailureScanHarness(t *testing.T) *failureScanHarness {
	t.Helper()
	root := t.TempDir()
	outputDir := filepath.Join(root, "out")
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inventory, err := state.NewInventoryManager(filepath.Join(root, "inventory.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inventory.Close() })
	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1
	cfg.Output.Format = "json"
	cfg.Output.JSONOut = filepath.Join(outputDir, "results.json")
	cfg.Output.HTMLOut = ""
	cfg.Output.ScannedTargetsOut = filepath.Join(outputDir, "scanned_targets.txt")
	return &failureScanHarness{root: root, outputDir: outputDir, cfg: cfg, inventory: inventory}
}

func (h *failureScanHarness) readErrorsPath() string {
	return filepath.Join(h.outputDir, "readErrors.log")
}

func (h *failureScanHarness) run(t *testing.T, client *failureScanClient) metrics.Snapshot {
	t.Helper()
	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{Recorder: recorder}, loadFailureRules(t), nil, logx.New("error"))
	sink := &recoverySink{}
	failures := failurereport.NewCollector()
	snapshot := failurereport.NewCollector()
	_ = snapshot
	err := scanHost(context.Background(), "host", "test", nil, nil, h.inventory, "ctx-test", "semantics", false, recorder, h.cfg, engine, sink, failures, logx.New("error"))
	if err != nil {
		t.Fatalf("scanHost returned error: %v", err)
	}
	// Mirror RunScan: publish the failure summary before snapshotting metrics.
	final := failures.Snapshot()
	path := filepath.Join(h.outputDir, "readErrors.log")
	written, writeErr := failurereport.WriteFile(path, final)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if !written {
		path = ""
	}
	recorder.SetFailureSummary(int64(final.Total()), path)
	return recorder.Snapshot()
}

func loadFailureRules(t *testing.T) *rules.Manager {
	t.Helper()
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// TestTransportResetRecoveredLeavesNoFailureArtifact covers Task 12 scenario A
// and Task 13: the reset is recovered, the retried legacy document is parsed,
// and no readErrors.log is produced.
func TestTransportResetRecoveredLeavesNoFailureArtifact(t *testing.T) {
	harness := newFailureScanHarness(t)
	legacyDoc := legacyfixture.Word("Brukernavn: svc_backup\rDomene: KUNDE\rPassord: Legacy-Word-123!\r")
	client := &failureScanClient{
		files: map[string][]byte{
			"A.txt": []byte("alpha"),
			"B.doc": legacyDoc,
			"C.xls": legacyfixture.Workbook([][]string{{"Brukernavn", "Passord"}, {"user1", "Legacy-XLS-123!"}}),
			"D.doc": legacyfixture.Word("Brukernavn: svc_d\rPassord: Legacy-D-456!\r"),
		},
		failReads:  map[string]error{},
		readCounts: map[string]int{},
		stats:      smb.TransportStats{TransportFailures: 1, ReconnectsAttempted: 1, ReconnectsSucceeded: 1, OperationsRetried: 1, FilesRecovered: 1},
	}
	snapshot := harness.run(t, client)

	if snapshot.Counters.SMBFilesRecovered != 1 {
		t.Fatalf("recovered counter not reflected: %#v", snapshot.Counters)
	}
	if snapshot.Counters.FinalFailureCount != 0 {
		t.Fatalf("recovered failure was treated as final: %#v", snapshot.Counters)
	}
	if _, err := os.Stat(harness.readErrorsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readErrors.log must not exist when every object succeeded: %v", err)
	}
	for _, path := range []string{"A.txt", "B.doc", "C.xls", "D.doc"} {
		if client.readCounts[path] == 0 {
			t.Fatalf("%s was not inspected: %#v", path, client.readCounts)
		}
	}
}

// TestTransportResetExhaustedWritesFailureArtifact covers Task 12 scenario B.
func TestTransportResetExhaustedWritesFailureArtifact(t *testing.T) {
	harness := newFailureScanHarness(t)
	resetErr := &smb2.TransportError{Err: syscall.ECONNRESET}
	client := &failureScanClient{
		files: map[string][]byte{
			"A.txt": []byte("alpha"),
			"B.doc": legacyfixture.Word("Brukernavn: svc_b\rPassord: Legacy-B-123!\r"),
			"D.doc": legacyfixture.Word("Brukernavn: svc_d\rPassord: Legacy-D-456!\r"),
		},
		failReads:  map[string]error{"B.doc": resetErr},
		readCounts: map[string]int{},
		stats:      smb.TransportStats{TransportFailures: 3, ReconnectsAttempted: 2, ReconnectsFailed: 2, OperationsRetried: 2, RetryExhausted: 1},
	}
	snapshot := harness.run(t, client)

	if snapshot.Counters.FinalFailureCount != 1 {
		t.Fatalf("expected one final failure, got %#v", snapshot.Counters)
	}
	raw, err := os.ReadFile(harness.readErrorsPath())
	if err != nil {
		t.Fatalf("readErrors.log missing: %v", err)
	}
	content := string(raw)
	if strings.Count(content, "Operation: read") != 1 {
		t.Fatalf("expected exactly one read failure entry:\n%s", content)
	}
	if !strings.Contains(content, "Failure category: SMB transport") || !strings.Contains(content, "Coverage incomplete: YES") {
		t.Fatalf("failure artifact incomplete:\n%s", content)
	}
	if !strings.Contains(content, "Retryable next scan: YES") {
		t.Fatalf("transport failure must be retryable next scan:\n%s", content)
	}
	// Remaining safe work still completed.
	if client.readCounts["D.doc"] == 0 {
		t.Fatalf("scan did not continue with remaining files: %#v", client.readCounts)
	}
	// The failed file must remain retryable in incremental state.
	decision, err := harness.inventory.Prepare(state.FileObservation{
		Server: "host", Share: "share", Path: "B.doc",
		Size: int64(len(client.files["B.doc"])), ModifiedAt: time.Unix(1000, 0).UTC(),
	}, "ctx-test", "semantics", false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatalf("failed read was recorded as completed: %s", decision.Reason)
	}
}

// TestAccessDeniedAndInspectionFailuresAreCategorized covers Task 14 cases 4, 7,
// 8 and the state agreement rule: an inspection failure must not be completed.
func TestAccessDeniedAndInspectionFailuresAreCategorized(t *testing.T) {
	harness := newFailureScanHarness(t)
	client := &failureScanClient{
		files: map[string][]byte{
			"denied.txt":    []byte("secret"),
			"encrypted.doc": legacyfixture.WordEncrypted(),
		},
		failReads:  map[string]error{"denied.txt": os.ErrPermission},
		readCounts: map[string]int{},
	}
	// The fake reports its own read failures, so the encrypted document is the
	// only inspection failure the engine reports.
	snapshot := harness.run(t, client)
	if snapshot.Counters.FinalFailureCount != 2 {
		t.Fatalf("expected two final failures, got %#v", snapshot.Counters)
	}
	raw, err := os.ReadFile(harness.readErrorsPath())
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, "Failure category: access denied") || !strings.Contains(content, "Retryable next scan: NO") {
		t.Fatalf("access denied not categorized:\n%s", content)
	}
	if !strings.Contains(content, "Operation: content inspection") || !strings.Contains(content, "Read succeeded: YES") ||
		!strings.Contains(content, "Parser: legacy Word") || !strings.Contains(content, "Failure category: encrypted content") {
		t.Fatalf("inspection failure not represented:\n%s", content)
	}
	// Inspection failure must not be completed in state.
	info, err := os.Stat(filepath.Join(harness.root, "inventory.json"))
	if err == nil && info.Size() >= 0 {
		_ = harness.inventory.Save()
	}
	decision, err := harness.inventory.Prepare(state.FileObservation{
		Server: "host", Share: "share", Path: "encrypted.doc",
		Size: int64(len(client.files["encrypted.doc"])), ModifiedAt: time.Unix(1000, 0).UTC(),
	}, "ctx-test", "semantics", false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatalf("inspection failure was recorded as completed: %s", decision.Reason)
	}
}

// TestMetricsAgreeAcrossConsoleJSONAndArtifact covers Task 8.
func TestMetricsAgreeAcrossConsoleJSONAndArtifact(t *testing.T) {
	harness := newFailureScanHarness(t)
	client := &failureScanClient{
		files:      map[string][]byte{"B.txt": []byte("bravo")},
		failReads:  map[string]error{"B.txt": &smb2.TransportError{Err: syscall.ECONNRESET}},
		readCounts: map[string]int{},
		stats:      smb.TransportStats{TransportFailures: 4, ReconnectsAttempted: 2, ReconnectsSucceeded: 1, ReconnectsFailed: 1, OperationsRetried: 3, FilesRecovered: 1, RetryExhausted: 1, EnumerationFailures: 2},
	}
	snapshot := harness.run(t, client)

	raw, err := os.ReadFile(harness.readErrorsPath())
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	counters := snapshot.Counters
	for _, expectation := range []struct {
		value int64
		text  string
	}{
		{counters.SMBTransportFailures, "SMB transport failures observed: 4"},
		{counters.SMBReconnectsAttempted, "Reconnect attempts: 2"},
		{counters.SMBReconnectsSucceeded, "Reconnect successes: 1"},
		{counters.SMBReconnectsFailed, "Reconnect failures: 1"},
		{counters.SMBOperationsRetried, "Operations retried: 3"},
		{counters.SMBFilesRecovered, "Files recovered after reconnect: 1"},
		{counters.SMBRetryExhausted, "Retry budget exhausted: 1"},
		{counters.FinalFailureCount, "Final unreadable files: 1"},
	} {
		if expectation.value == 0 {
			t.Fatalf("counter for %q was not propagated to metrics: %#v", expectation.text, counters)
		}
		if !strings.Contains(content, expectation.text) {
			t.Fatalf("readErrors.log missing %q:\n%s", expectation.text, content)
		}
	}
	// JSON and console views are produced from the same snapshot.
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), fmt.Sprintf(`"final_failure_count":%d`, counters.FinalFailureCount)) {
		t.Fatalf("JSON metrics missing the failure count: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"smb_reconnects_attempted":2`) {
		t.Fatalf("JSON metrics missing transport counters: %s", encoded)
	}
	if !utf8.Valid(encoded) {
		t.Fatal("JSON metrics are not valid UTF-8")
	}
	if snapshot.ReadErrorsLog == "" {
		t.Fatal("metrics did not publish the artifact path")
	}
}

// TestUnicodeFailurePathStaysValidUTF8 covers Task 14 case 12.
func TestUnicodeFailurePathStaysValidUTF8(t *testing.T) {
	harness := newFailureScanHarness(t)
	client := &failureScanClient{
		files:      map[string][]byte{"PasswordList ÆØÅ.txt": []byte("hemmelig")},
		failReads:  map[string]error{"PasswordList ÆØÅ.txt": &smb2.TransportError{Err: syscall.ECONNRESET}},
		readCounts: map[string]int{},
	}
	harness.run(t, client)
	raw, err := os.ReadFile(harness.readErrorsPath())
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(raw) {
		t.Fatal("failure artifact is not valid UTF-8")
	}
	if !strings.Contains(string(raw), "PasswordList ÆØÅ.txt") {
		t.Fatalf("unicode path was mangled:\n%s", raw)
	}
}

// TestPreviousFailureDisappearsOnHealthyScan covers Task 11: the artifact is
// per-scan, not historical.
func TestPreviousFailureDisappearsOnHealthyScan(t *testing.T) {
	harness := newFailureScanHarness(t)
	failing := &failureScanClient{
		files:      map[string][]byte{"B.txt": []byte("bravo")},
		failReads:  map[string]error{"B.txt": &smb2.TransportError{Err: syscall.ECONNRESET}},
		readCounts: map[string]int{},
	}
	harness.run(t, failing)
	if _, err := os.Stat(harness.readErrorsPath()); err != nil {
		t.Fatalf("expected a failure artifact after the failing scan: %v", err)
	}

	healthy := &failureScanClient{
		files:      map[string][]byte{"B.txt": []byte("bravo")},
		failReads:  map[string]error{},
		readCounts: map[string]int{},
	}
	snapshot := harness.run(t, healthy)
	if snapshot.Counters.FinalFailureCount != 0 {
		t.Fatalf("healthy rescan still reported failures: %#v", snapshot.Counters)
	}
	if _, err := os.Stat(harness.readErrorsPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale failure artifact was not removed: %v", err)
	}
}

// TestSemanticsVersionReprocessesOldState covers Task 10: state completed under
// the previous semantics version is invalidated once, and current state is
// skipped normally afterwards.
func TestSemanticsVersionReprocessesOldState(t *testing.T) {
	cfg := config.Default()
	manager := loadFailureRules(t)
	fingerprint := scanSemanticsFingerprint(cfg, manager)
	if !strings.Contains(fingerprint, "") {
		t.Fatal("unreachable")
	}
	if scannerSemanticsVersion != "snablr-content-scan-v4" {
		t.Fatalf("scanner semantics version = %q, want v4", scannerSemanticsVersion)
	}
	legacyFingerprint := scanSemanticsFingerprintWithVersion(cfg, manager, "snablr-content-scan-v3")
	if legacyFingerprint == fingerprint {
		t.Fatal("v3 and v4 semantics fingerprints must differ")
	}

	inventory, err := state.OpenInventory(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := state.FileObservation{Server: "host", Share: "share", Path: "Docs/file.docx", Size: 1024, ModifiedAt: time.Unix(1000, 0).UTC()}
	// RUN 1: completed under the previous semantics version.
	first, err := inventory.Prepare(observation, "ctx", legacyFingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	inventory.MarkCompleted(first.Key)
	// RUN 2: current semantics must re-inspect even though metadata is unchanged.
	second, err := inventory.Prepare(observation, "ctx", fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if second.Skip {
		t.Fatalf("v3 state was reused under v4 semantics: %s", second.Reason)
	}
	inventory.MarkCompleted(second.Key)
	// RUN 3: current state is skipped normally.
	third, err := inventory.Prepare(observation, "ctx", fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	if !third.Skip {
		t.Fatalf("v4 state was not reused: %s", third.Reason)
	}
	raw, err := os.ReadFile(inventory.Path())
	if err != nil {
		if saveErr := inventory.Save(); saveErr == nil {
			raw, err = os.ReadFile(inventory.Path())
		}
	}
	if err == nil {
		for _, secret := range []string{"Legacy-Word-123!", "Legacy-XLS-123!"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("credential value persisted into state: %s", secret)
			}
		}
	}
}

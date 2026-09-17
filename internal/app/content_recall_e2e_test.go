package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/credentialanalysis"
	"snablr/internal/metrics"
	"snablr/internal/officefixture"
	"snablr/internal/output"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// contentRecallScanClient is a healthy scripted share used to prove that
// ordinary content credentials still reach the operator-facing credential
// export through the real application scan path.
type contentRecallScanClient struct {
	files      map[string][]byte
	failReads  map[string]error
	readCounts map[string]int
	readOK     map[string]int
}

func (c *contentRecallScanClient) SetMaxReadSize(int64)                   {}
func (c *contentRecallScanClient) Close() error                           { return nil }
func (c *contentRecallScanClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (c *contentRecallScanClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *contentRecallScanClient) TransportStats() smb.TransportStats { return smb.TransportStats{} }
func (c *contentRecallScanClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
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
func (c *contentRecallScanClient) ReadFile(_ string, path string) ([]byte, error) {
	normalized := strings.ReplaceAll(path, `\`, "/")
	c.readCounts[normalized]++
	if err := c.failReads[normalized]; err != nil {
		return nil, err
	}
	c.readOK[normalized]++
	return c.files[normalized], nil
}

// TestScanHostContentCredentialsReachCredsOut is the end-to-end recall control:
// a boring-named INI file, a normal DOCX and a plain TXT must all be enumerated,
// read, harvested and exported by the same scanHost path used for discovered
// files. It deliberately avoids filename credential vocabulary so a
// filename-only finding cannot satisfy it.
func TestScanHostContentCredentialsReachCredsOut(t *testing.T) {
	files := map[string][]byte{
		"readme.txt":           []byte("nothing interesting here\n"),
		"settings.ini":         []byte("[Default]\nAdminPassword=Synthetic-Admin-123!\n"),
		"OperationsGuide.docx": officefixture.DOCX(officefixture.Paragraph("Passordet er; Synthetic-Docx-123!")),
		"notes.txt":            []byte("Password=Synthetic-Txt-123!\n"),
	}
	client := &contentRecallScanClient{files: files, failReads: map[string]error{}, readCounts: map[string]int{}, readOK: map[string]int{}}

	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.txt")

	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1
	cfg.Output = config.OutputConfig{Format: "console", NoTUI: true, CredsOut: credsPath}

	manager, issues, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(issues) > 0 {
		t.Fatalf("rule issues: %v", issues)
	}

	sink, err := output.NewWriter(cfg.Output)
	if err != nil {
		t.Fatalf("create output writer: %v", err)
	}

	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{
		Recorder:         recorder,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     scanReadLimit(cfg),
		SnippetBytes:     120,
	}, manager, sink, logx.New("error"))
	if exporter, ok := sink.(scanner.SensitiveCredentialExporter); ok {
		engine.SetCredentialExporter(exporter)
	}
	if candidates, ok := sink.(scanner.CredentialCandidateSink); ok {
		engine.SetCredentialCandidateSink(candidates)
	}

	if err := scanHost(context.Background(), "host", "test", nil, nil, nil, "ctx-content-recall", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error")); err != nil {
		t.Fatalf("scanHost returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close output writer: %v", err)
	}

	// Every control file must have been content-read, not merely enumerated.
	for _, name := range []string{"settings.ini", "OperationsGuide.docx", "notes.txt"} {
		if client.readCounts[name] == 0 {
			t.Fatalf("control file %s was never content-read (reads=%v)", name, client.readCounts)
		}
	}

	raw, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatalf("read creds-out: %v", err)
	}
	exported := string(raw)
	for _, want := range []string{"Synthetic-Admin-123!", "Synthetic-Docx-123!", "Synthetic-Txt-123!"} {
		if !strings.Contains(exported, want) {
			t.Fatalf("creds-out is missing %q\n--- creds-out ---\n%s", want, exported)
		}
	}

	snapshot := recorder.Snapshot()
	if snapshot.Counters.FilesRead == 0 {
		t.Fatal("no successful content reads were counted")
	}
}

// recallRecordingSink records what the engine reported per file while still
// writing the operator-facing artifacts through the real output writer.
type recallRecordingSink struct {
	inner scanner.FindingSink
	mu    sync.Mutex
	// findingsByPath records the signal types reported for each file path, so a
	// filename-only finding can be told apart from a content finding.
	signalsByPath map[string][]string
	rulesByPath   map[string][]string
	candidates    []credentialanalysis.Candidate
}

func (s *recallRecordingSink) WriteFinding(f scanner.Finding) error {
	s.mu.Lock()
	s.signalsByPath[f.FilePath] = append(s.signalsByPath[f.FilePath], f.MatchedSignalTypes...)
	s.rulesByPath[f.FilePath] = append(s.rulesByPath[f.FilePath], f.RuleID)
	s.mu.Unlock()
	return s.inner.WriteFinding(f)
}

func (s *recallRecordingSink) Close() error { return s.inner.Close() }

func (s *recallRecordingSink) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	s.mu.Lock()
	s.candidates = append(s.candidates, candidate)
	s.mu.Unlock()
	if recorder, ok := s.inner.(scanner.CredentialCandidateSink); ok {
		return recorder.RecordCredentialCandidate(candidate)
	}
	return nil
}

func (s *recallRecordingSink) RecordHost(host string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}
}

func (s *recallRecordingSink) RecordShare(host, share string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordShare(host, share)
	}
}

func (s *recallRecordingSink) RecordFile(meta scanner.FileMetadata) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordFile(meta)
	}
}

func (s *recallRecordingSink) RecordSkip(meta scanner.FileMetadata, reason string) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordSkip(meta, reason)
	}
}

func (s *recallRecordingSink) RecordReadError(meta scanner.FileMetadata, err error) {
	if observer, ok := s.inner.(scanner.ScanObserver); ok {
		observer.RecordReadError(meta, err)
	}
}

func (s *recallRecordingSink) hasSignalType(path, signalType string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, observed := range s.signalsByPath[path] {
		if strings.EqualFold(observed, signalType) {
			return true
		}
	}
	return false
}

func (s *recallRecordingSink) hasRulePrefix(path, prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rule := range s.rulesByPath[path] {
		if strings.HasPrefix(rule, prefix) {
			return true
		}
	}
	return false
}

// TestFilenameFindingIsNotContentReadEvidence separates metadata evidence from
// content evidence. A filename match is produced from the directory listing, so
// it can appear for a file whose content was never successfully read; that must
// never be mistaken for content inspection. A structured content credential, by
// contrast, must come with an actual successful read.
func TestFilenameFindingIsNotContentReadEvidence(t *testing.T) {
	files := map[string][]byte{
		// Filename vocabulary matches, but every read of this file fails, which
		// is exactly the live symptom: metadata findings remain visible while
		// the content is never inspected.
		"password_backup.txt": []byte("Password=Should-Not-Be-Harvested-999!\n"),
		// Structured content credential in a boring-named file.
		"settings.ini": []byte("[Default]\nAdminPassword=Synthetic-Admin-123!\n"),
	}
	client := &contentRecallScanClient{
		files:      files,
		failReads:  map[string]error{"password_backup.txt": fmt.Errorf("injected unreadable file")},
		readCounts: map[string]int{},
		readOK:     map[string]int{},
	}

	oldClient := newScanClientFunc
	defer func() { newScanClientFunc = oldClient }()
	newScanClientFunc = func() scanClient { return client }

	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.txt")

	cfg := config.Default()
	cfg.Scan.Username = "user"
	cfg.Scan.Password = "password"
	cfg.Scan.WorkerCount = 1
	cfg.Output = config.OutputConfig{Format: "console", NoTUI: true, CredsOut: credsPath}

	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	inner, err := output.NewWriter(cfg.Output)
	if err != nil {
		t.Fatalf("create output writer: %v", err)
	}
	sink := &recallRecordingSink{inner: inner, signalsByPath: map[string][]string{}, rulesByPath: map[string][]string{}}

	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{
		Recorder:         recorder,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     scanReadLimit(cfg),
		SnippetBytes:     120,
	}, manager, sink, logx.New("error"))
	engine.SetCredentialCandidateSink(sink)

	if err := scanHost(context.Background(), "host", "test", nil, nil, nil, "ctx-content-recall", "semantics", false, recorder, cfg, engine, sink, nil, logx.New("error")); err != nil {
		t.Fatalf("scanHost returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	if client.readOK["password_backup.txt"] != 0 {
		t.Fatal("unreadable file reported a successful content read")
	}
	if !sink.hasRulePrefix("password_backup.txt", "filename.") {
		t.Fatalf("expected a filename finding for password_backup.txt, got %v", sink.rulesByPath)
	}
	if client.readOK["settings.ini"] == 0 {
		t.Fatal("content credential file was never successfully read")
	}
	sink.mu.Lock()
	candidates := append([]credentialanalysis.Candidate(nil), sink.candidates...)
	sink.mu.Unlock()
	found := false
	for _, candidate := range candidates {
		if candidate.Value == "Synthetic-Admin-123!" {
			found = true
		}
		if candidate.Value == "Should-Not-Be-Harvested-999!" {
			t.Fatal("a value from a file that was never read produced a content credential")
		}
	}
	if !found {
		t.Fatalf("no content credential candidate for the INI control: %#v", candidates)
	}
}

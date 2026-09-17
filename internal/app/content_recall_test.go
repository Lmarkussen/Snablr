package app

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/officefixture"
	"snablr/internal/output"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// trailingStatusClient returns each file's real bytes together with a non-nil
// status, reproducing how SMB servers commonly deliver end-of-file. The bytes
// must still be read and analyzed.
type trailingStatusClient struct {
	files map[string][]byte
}

func (c *trailingStatusClient) SetMaxReadSize(int64)                   {}
func (c *trailingStatusClient) Close() error                           { return nil }
func (c *trailingStatusClient) ConnectWithAuth(string, smb.Auth) error { return nil }
func (c *trailingStatusClient) ListShares() ([]smb.ShareInfo, error) {
	return []smb.ShareInfo{{Name: "share"}}, nil
}
func (c *trailingStatusClient) WalkShareWithOptions(_ string, _ smb.WalkOptions, fn func(smb.RemoteFile) error) error {
	for _, name := range []string{"settings.txt", "settings.ini", "utf16-notes.txt", "OperationsGuide.docx"} {
		if err := fn(smb.RemoteFile{
			Host: "fileserver.example.test", Share: "share", Path: name, Name: name,
			Size: int64(len(c.files[name])), ModifiedAt: time.Unix(1000, 0).UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
func (c *trailingStatusClient) ReadFile(_ string, path string) ([]byte, error) {
	key := strings.ReplaceAll(path, `\`, "/")
	if _, ok := c.files[key]; !ok {
		return nil, errors.New("not found")
	}
	return c.files[key], errors.New("invalid response error: broken error response format")
}

func utf16LE(text string) []byte {
	encoded := utf16.Encode([]rune(text))
	out := make([]byte, 0, 2+len(encoded)*2)
	out = append(out, 0xff, 0xfe) // UTF-16LE BOM
	for _, unit := range encoded {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return out
}

// TestContentCredentialsSurviveTrailingSMBStatus is the recall regression for
// the live failure: an SMB read that delivers the file's bytes and then reports
// a status must not throw the content away. Boring filenames are deliberate.
func TestContentCredentialsSurviveTrailingSMBStatus(t *testing.T) {
	files := map[string][]byte{
		"settings.txt":         []byte("AdminPassword=Synthetic-Txt-123!\n"),
		"settings.ini":         []byte("[Default]\nAdminPassword=Synthetic-Ini-123!\n"),
		"utf16-notes.txt":      utf16LE("AdminPassword=Synthetic-Utf16-123!\r\n"),
		"OperationsGuide.docx": officefixture.DOCX(officefixture.Paragraph("Passordet er; Synthetic-Docx-123!")),
	}
	client := &trailingStatusClient{files: files}
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
		t.Fatalf("output writer: %v", err)
	}
	recorder := metrics.NewCollector()
	engine := scanner.NewEngine(scanner.Options{
		Recorder:         recorder,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     scanReadLimit(cfg),
		SnippetBytes:     120,
	}, manager, sink, logx.New("error"))
	if candidates, ok := sink.(scanner.CredentialCandidateSink); ok {
		engine.SetCredentialCandidateSink(candidates)
	} else {
		t.Fatal("output writer does not accept credential candidates")
	}

	if err := scanHost(context.Background(), "fileserver.example.test", "test", nil, nil, nil, "ctx", "semantics", false, recorder, cfg, engine, sink, logx.New("error")); err != nil {
		t.Fatalf("scanHost: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	if snap := recorder.Snapshot(); snap.Counters.FilesRead == 0 {
		t.Fatal("no successful content reads were counted")
	}
	raw, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatalf("read creds-out: %v", err)
	}
	exported := string(raw)
	for _, want := range []string{"Synthetic-Txt-123!", "Synthetic-Ini-123!", "Synthetic-Utf16-123!", "Synthetic-Docx-123!"} {
		if !strings.Contains(exported, want) {
			t.Fatalf("creds-out missing %q\n%s", want, exported)
		}
	}
}

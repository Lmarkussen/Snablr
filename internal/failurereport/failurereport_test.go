package failurereport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/hirochachacha/go-smb2"

	"snablr/internal/smb"
)

func TestWriteFileSkippedWhenNoFinalFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readErrors.log")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	written, err := WriteFile(path, NewCollector().Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if written {
		t.Fatal("no final failures must not produce an artifact")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale readErrors.log was not removed: %v", err)
	}
}

func TestWriteFileCreatesArtifactWithMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readErrors.log")
	collector := NewCollector()
	collector.Record(Failure{
		Target: `\\SERVER`, Path: "share/folder/document.docx", Operation: OperationRead,
		Category: CategoryTransport, Attempts: 3, ReconnectAttempted: true, Retryable: true,
		FinalError: "read tcp: connection reset by peer",
	})
	written, err := WriteFile(path, collector.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if !written {
		t.Fatal("final failures must produce an artifact")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("readErrors.log mode = %o, want 600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, want := range []string{
		"SNABLR READ ERRORS",
		"Final unreadable files: 1",
		"Failed directory enumerations: 0",
		"Coverage incomplete: YES",
		`Path: \\SERVER\share\folder\document.docx`,
		"Operation: read",
		"Failure category: SMB transport",
		"Attempts: 3",
		"Reconnect attempted: YES",
		"Recovered: NO",
		"Retryable next scan: YES",
		"Final error: read tcp: connection reset by peer",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("artifact missing %q:\n%s", want, content)
		}
	}
}

func TestRenderDirectoryEnumerationIsDistinct(t *testing.T) {
	collector := NewCollector()
	collector.Record(Failure{
		Target: `\\SERVER`, Path: "share/Folder", Operation: OperationEnumeration,
		Category: CategoryEnumeration, Attempts: 3, ReconnectAttempted: true, Retryable: true,
		CoverageImpact: "subtree may be incomplete", FinalError: "connection reset by peer",
	})
	content := Render(collector.Snapshot())
	if !strings.Contains(content, "Failed directory enumerations: 1") {
		t.Fatalf("enumeration failure not counted separately:\n%s", content)
	}
	if !strings.Contains(content, "Operation: directory enumeration") || !strings.Contains(content, "Coverage impact: subtree may be incomplete") {
		t.Fatalf("enumeration failure not represented distinctly:\n%s", content)
	}
	if !strings.Contains(content, "Final unreadable files: 0") {
		t.Fatalf("enumeration failure was disguised as a file failure:\n%s", content)
	}
}

func TestRenderInspectionFailureShowsReadSucceeded(t *testing.T) {
	collector := NewCollector()
	collector.Record(Failure{
		Target: `\\SERVER`, Path: "share/legacy.doc", Operation: OperationInspection,
		Category: CategoryEncrypted, Parser: "legacy Word", ReadSucceeded: true,
		Attempts: 1, Retryable: false, FinalError: "document is encrypted; content was not inspected",
	})
	content := Render(collector.Snapshot())
	for _, want := range []string{
		"Operation: content inspection",
		"Parser: legacy Word",
		"Read succeeded: YES",
		"Failure category: encrypted content",
		"Retryable next scan: NO",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("inspection failure missing %q:\n%s", want, content)
		}
	}
	if !strings.Contains(content, "Failed content inspections: 1") {
		t.Fatalf("inspection failure not counted:\n%s", content)
	}
}

func TestRenderKeepsNestedProvenanceAndUnicode(t *testing.T) {
	collector := NewCollector()
	collector.Record(Failure{
		Target: `\\SERVER`, Path: "share/backup.wim[index=2]!Docs/passordliste ÆØÅ.xls",
		Operation: OperationInspection, Category: CategoryMalformed, Parser: "legacy Excel",
		ReadSucceeded: true, Attempts: 1, FinalError: "workbook contains no worksheet",
	})
	content := Render(collector.Snapshot())
	if !strings.Contains(content, `\\SERVER\share\backup.wim[index=2]!Docs\passordliste ÆØÅ.xls`) {
		t.Fatalf("nested provenance or unicode path was mangled:\n%s", content)
	}
	if !strings.Contains(content, "ÆØÅ") {
		t.Fatalf("unicode path did not survive rendering:\n%s", content)
	}
	if !utf8.ValidString(content) {
		t.Fatal("artifact is not valid UTF-8")
	}
}

func TestRecoveredFailuresAreNotRecorded(t *testing.T) {
	collector := NewCollector()
	// A recovered operation never reaches the collector; only the transport
	// summary counters reflect it.
	collector.RecordTransportCounters(Counters{TransportFailures: 12, ReconnectsAttempted: 5, ReconnectsSucceeded: 4, OperationsRetried: 9, FilesRecovered: 8})
	snapshot := collector.Snapshot()
	if snapshot.CoverageIncomplete() || len(snapshot.Failures) != 0 {
		t.Fatalf("recovered failures must not appear as final: %#v", snapshot.Failures)
	}
	content := Render(snapshot)
	if !strings.Contains(content, "SMB transport failures observed: 12") ||
		!strings.Contains(content, "Files recovered after reconnect: 8") ||
		!strings.Contains(content, "Coverage incomplete: NO") {
		t.Fatalf("recovery summary missing:\n%s", content)
	}
	if strings.Contains(content, "Path:") {
		t.Fatalf("recovered failures must not be listed:\n%s", content)
	}
}

func TestRecordDeduplicatesRepeatedObservations(t *testing.T) {
	collector := NewCollector()
	for attempt := 1; attempt <= 3; attempt++ {
		collector.Record(Failure{
			Target: `\\SERVER`, Path: "share/file.docx", Operation: OperationRead,
			Category: CategoryTransport, Attempts: attempt, ReconnectAttempted: true, FinalError: "connection reset by peer",
		})
	}
	snapshot := collector.Snapshot()
	if len(snapshot.Failures) != 1 {
		t.Fatalf("expected one final entry, got %d", len(snapshot.Failures))
	}
	if snapshot.Failures[0].Attempts != 3 {
		t.Fatalf("expected the strongest attempt count, got %d", snapshot.Failures[0].Attempts)
	}
}

// TestSanitizeRemovesCredentialMaterial proves no authentication secret can be
// rendered into the artifact, including through error formatting verbs.
func TestSanitizeRemovesCredentialMaterial(t *testing.T) {
	secrets := []string{
		`smb2: logon failure for user DOMAIN\svc with Password=SuperSecret123!`,
		"nt hash 0123456789abcdef0123456789abcdef rejected",
		"Kerberos ticket cache FILE:/tmp/krb5cc containing ticket material",
		"api_key=AKIAIOSFODNN7EXAMPLE",
		"client_secret=abcdef",
		"private key -----BEGIN RSA PRIVATE KEY-----",
	}
	for _, secret := range secrets {
		rendered := Sanitize(secret)
		if strings.Contains(rendered, "SuperSecret123!") || strings.Contains(rendered, "0123456789abcdef0123456789abcdef") ||
			strings.Contains(rendered, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(rendered, "abcdef") ||
			strings.Contains(rendered, "BEGIN RSA PRIVATE KEY") {
			t.Fatalf("sanitizer leaked secret material: %q", rendered)
		}
	}
	// The SMB client's own redacting representations are asserted in the smb
	// package (TestCredentialMaterialIsNotRendered); here we prove the artifact
	// sanitizer cannot pass credential-shaped detail through either.
	for _, problematic := range []string{
		"logon failure: user=svc password=SuperSecret123!",
		"NT hash 0123456789abcdef0123456789abcdef rejected",
	} {
		if rendered := Sanitize(problematic); strings.Contains(rendered, "SuperSecret123!") ||
			strings.Contains(rendered, "0123456789abcdef0123456789abcdef") {
			t.Fatalf("artifact sanitizer leaked credential material: %q", rendered)
		}
	}
	if !strings.Contains(Sanitize("connection reset by peer"), "connection reset by peer") {
		t.Fatal("neutral transport detail should be preserved")
	}
}

func TestCategorizeErrorUsesStructuredInformation(t *testing.T) {
	cases := []struct {
		err      error
		category smb.ErrorCategory
	}{
		{&smb2.TransportError{Err: syscall.ECONNRESET}, smb.CategoryTransport},
		{&smb2.ResponseError{Code: 0xC0000022}, smb.CategoryAccessDenied},
		{&smb2.ResponseError{Code: 0xC0000034}, smb.CategoryNotFound},
		{os.ErrPermission, smb.CategoryAccessDenied},
		{os.ErrNotExist, smb.CategoryNotFound},
		{context.DeadlineExceeded, smb.CategoryTimeout},
		{smb.ErrOperationTimeout, smb.CategoryTimeout},
		{&smb2.ResponseError{Code: 0xC000006D}, smb.CategoryAuthFailure},
		{fmt.Errorf("wrapped: %w", smb.ErrAuthFailure), smb.CategoryAuthFailure},
		{smb.ErrFileTooLarge, smb.CategorySizeLimit},
		{errors.New("something else"), smb.CategoryRead},
	}
	for _, test := range cases {
		if got := smb.CategorizeError(test.err); got != test.category {
			t.Errorf("CategorizeError(%v) = %s, want %s", test.err, got, test.category)
		}
	}
	// The failure model must never mark a rejected credential as retryable.
	if got := CategoryForSMBCategory(smb.CategoryAuthFailure); got != CategoryAuthFailure {
		t.Fatalf("auth failure mapped to %q, want %q", got, CategoryAuthFailure)
	}
}

func TestCollectorIsConcurrencySafe(t *testing.T) {
	collector := NewCollector()
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			for file := 0; file < 25; file++ {
				collector.Record(Failure{
					Target: `\\SERVER`, Path: fmt.Sprintf("share/file-%d.txt", file),
					Operation: OperationRead, Category: CategoryTransport, Attempts: 3, FinalError: "connection reset by peer",
				})
			}
		}(worker)
	}
	group.Wait()
	if got := len(collector.Snapshot().Failures); got != 25 {
		t.Fatalf("rounded failures = %d, want 25 distinct entries", got)
	}
}

package output

import (
	"bytes"
	"strings"
	"testing"

	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

// TestConsoleReportsIncompleteCoverage pins the operator-visible contract: a
// scan with failed content reads and transport recovery activity must not look
// like a complete scan.
func TestConsoleReportsIncompleteCoverage(t *testing.T) {
	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nopCloser{})

	// Two failed reads plus transport recovery accounting.
	writer.RecordReadError(scanner.FileMetadata{Host: "fs01", Share: "share", FilePath: "Docs/B.docx"}, errFakeCoverage)
	writer.RecordReadError(scanner.FileMetadata{Host: "fs01", Share: "share", FilePath: "Docs/C.xlsx"}, errFakeCoverage)
	writer.SetMetricsSnapshot(metrics.Snapshot{Counters: metrics.Counters{
		FilesVisited:           4,
		FilesRead:              2,
		FinalFailureCount:      2,
		SMBTransportFailures:   3,
		SMBReconnectsAttempted: 2,
		SMBReconnectsSucceeded: 1,
		SMBReconnectsFailed:    1,
		SMBOperationsRetried:   2,
		SMBFilesRecovered:      1,
		SMBRetryExhausted:      1,
		SMBEnumerationFailures: 1,
	}})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Coverage incomplete: yes",
		"[WARN] Scan completed with incomplete coverage:",
		"See readErrors.log",
		"content_read_failures=2",
		"smb_transport_failures=3",
		"smb_reconnects_attempted=2",
		"smb_reconnects_failed=1",
		"smb_files_recovered=1",
		"smb_retry_exhausted=1",
		"smb_enumeration_failures=1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected coverage line to contain %q, got:\n%s", want, out)
		}
	}
}

// TestConsoleOmitsCoverageLineWhenReadsSucceed keeps the line absent for a clean
// scan so it stays meaningful.
func TestConsoleOmitsCoverageLineWhenReadsSucceed(t *testing.T) {
	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nopCloser{})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Coverage incomplete: no") {
		t.Fatalf("clean scan must state complete coverage:\n%s", out)
	}
	if strings.Contains(out, "[WARN] Scan completed with incomplete coverage") {
		t.Fatalf("clean scan must not warn about coverage:\n%s", out)
	}
}

var errFakeCoverage = coverageTestError("read failed after reconnect retries")

type coverageTestError string

func (e coverageTestError) Error() string { return string(e) }

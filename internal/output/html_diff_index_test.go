package output

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

func TestAttachedHTMLUsesStreamingBaselinePath(t *testing.T) {
	state, err := store.Open(filepath.Join(t.TempDir(), "state.db"), store.Options{ScanID: "streaming-baseline", BatchSize: 1, QueueSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	current := scanner.Finding{RuleID: "rule.current", RuleName: "Current", Severity: "high", Category: "credentials", Host: "host", Share: "share", FilePath: "current.txt", Match: "current"}
	removed := scanner.Finding{RuleID: "rule.removed", RuleName: "Removed", Severity: "medium", Category: "credentials", Host: "host", Share: "share", FilePath: "removed.txt", Match: "baseline-only"}
	if err := state.RecordFinding(current); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	payload, err := json.Marshal(map[string]any{"summary": map[string]any{}, "findings": []scanner.Finding{current, removed}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer, err := NewHTMLWriter(&output, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.SetBaselinePath(baselinePath); err != nil {
		t.Fatal(err)
	}
	AttachSQLiteStore(writer, state)
	if err := writer.RecordCredentialCandidate(credentialanalysis.Candidate{
		Verification: credentialanalysis.Confirmed, CredentialType: "password", Identity: "svc", Value: "secret-value",
		Host: current.Host, Share: current.Share, Path: current.FilePath,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.RecordCredentialCandidate(credentialanalysis.Candidate{
		Verification: credentialanalysis.Review, CredentialType: "password", Identity: "svc", Value: "secret-value",
		Host: current.Host, Share: current.Share, Path: "second.txt",
	}); err != nil {
		t.Fatal(err)
	}
	if len(writer.candidates) != 0 {
		t.Fatalf("attached writer retained %d credential candidates", len(writer.candidates))
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	var persistedCandidates int
	if err := state.IterateCredentials(context.Background(), 16, func(batch []credentialanalysis.Candidate) error {
		persistedCandidates += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if persistedCandidates != 2 {
		t.Fatalf("persisted candidates=%d", persistedCandidates)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Unchanged Findings", "Removed Findings", "baseline-only", `href="#` + findingAnchor(current) + `"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("streaming baseline HTML omitted %q", want)
		}
	}
	if !strings.Contains(text, "secret-value") {
		t.Fatal("attached HTML omitted persisted credential analysis row")
	}
	if !strings.Contains(text, "Cross-File Credential Relationships") || !strings.Contains(text, "same material") {
		t.Fatal("attached HTML omitted persisted credential correlation")
	}
}

func TestHTMLReportBaselineIteratorHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	index, err := BuildHTMLReportIndexWithBaselineIterator(ctx, func(context.Context, func(scanner.Finding) error) error { return nil }, func(context.Context, func(scanner.Finding) error) error {
		return context.Canceled
	})
	if err == nil || index != nil {
		t.Fatalf("expected cancelled baseline build, index=%v err=%v", index, err)
	}
}

func TestAttachedHTMLPersistedCredentialMeasurement(t *testing.T) {
	state, err := store.Open(filepath.Join(t.TempDir(), "measurement.db"), store.Options{ScanID: "html-measurement", BatchSize: 64, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	for i := 0; i < 2000; i++ {
		if err := state.RecordCredential(credentialanalysis.Candidate{
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "token",
			Identity:       "user-" + strconv.Itoa(i),
			Value:          "value-" + strconv.Itoa(i),
			Path:           "file-" + strconv.Itoa(i) + ".ini",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	writer, err := NewHTMLWriter(io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	AttachSQLiteStore(writer, state)
	start := time.Now()
	stop := make(chan struct{})
	done := make(chan struct{})
	var maxRSS, maxHeap uint64
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				if stats.HeapAlloc > maxHeap {
					maxHeap = stats.HeapAlloc
				}
				if rss := attachedProcessRSSBytes(); rss > maxRSS {
					maxRSS = rss
				}
			case <-stop:
				return
			}
		}
	}()
	if err := writer.Close(); err != nil {
		close(stop)
		<-done
		t.Fatal(err)
	}
	close(stop)
	<-done
	t.Logf("attached_html candidates=2000 close=%s peak_heap=%d bytes peak_rss=%d bytes", time.Since(start), maxHeap, maxRSS)
}

func attachedProcessRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				return value * 1024
			}
		}
	}
	return 0
}

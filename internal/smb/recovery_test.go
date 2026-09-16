package smb

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"errors"
)

// TestReadFileRecoversFromResetAfterReconnect is A17 case 1 and 6: the first
// read dies with ECONNRESET, the client reconnects with the same credentials,
// retries that same file, and the following files are read on the new session.
func TestReadFileRecoversFromResetAfterReconnect(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.addFile("share", "B.docx", []byte("bravo"))
	server.addFile("share", "C.xlsx", []byte("charlie"))
	server.addFile("share", "D.txt", []byte("delta"))
	// Reading B kills the transport once.
	server.script(readKey("share", "B.docx"), opScript{err: resetError(), killTrunk: true})

	client := newFaultyClient(t, server)

	for _, name := range []string{"A.txt", "B.docx", "C.xlsx", "D.txt"} {
		data, err := client.ReadFile("share", name)
		if err != nil {
			t.Fatalf("read %s failed: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("read %s returned no data", name)
		}
	}

	stats := client.TransportStats()
	if stats.ReconnectsAttempted != 1 || stats.ReconnectsSucceeded != 1 {
		t.Fatalf("expected exactly one successful reconnect, got %#v", stats)
	}
	if stats.FilesRecovered != 1 {
		t.Fatalf("expected the failed file to be recovered, got %#v", stats)
	}
	if stats.RetryExhausted != 0 {
		t.Fatalf("unexpected retry exhaustion: %#v", stats)
	}
	if server.dialCount() != 2 { // initial connect + one reconnect
		t.Fatalf("dial count=%d, want 2", server.dialCount())
	}
	// The failed file is retried, not skipped: every file was opened at least
	// once and B was opened twice (fail + retry) with no duplicate findings.
	if server.reads != len([]string{"A.txt", "B.docx", "C.xlsx", "D.txt"})+1 {
		t.Fatalf("read operations=%d, want one retry for B only", server.reads)
	}
}

// TestReconnectPreservesCredentialContext is A4/A19: reconnects reuse the exact
// operator credential context (mode, identity, domain, and secret material) and
// never rotate, upgrade, or downgrade it.
func TestReconnectPreservesCredentialContext(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: resetError(), killTrunk: true})
	client := NewClient()
	client.dialer = server
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if _, err := client.ReadFile("share", "A.txt"); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(server.dialAuth) != 2 {
		t.Fatalf("expected two dials (connect + reconnect), got %d", len(server.dialAuth))
	}
	initial, reconnected := server.dialAuth[0], server.dialAuth[1]
	if initial != reconnected {
		t.Fatalf("reconnect changed the credential context: %#v vs %#v", initial, reconnected)
	}
	if reconnected.mode != AuthModePassword || reconnected.username != "operator" || reconnected.domain != "DOMAIN" {
		t.Fatalf("unexpected resolved identity after reconnect: mode=%s domain=%s", reconnected.mode, reconnected.domain)
	}
	if reconnected.password != "Secret-123!" {
		t.Fatalf("reconnect did not preserve the password credential")
	}
}

// TestReconnectPreservesNTHashMode covers PTH reconnects (A19).
func TestReconnectPreservesNTHashMode(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: resetError(), killTrunk: true})
	client := NewClient()
	client.dialer = server
	auth, err := NewNTHashAuth("operator", "DOMAIN", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectWithAuth("fileserver.example.test", auth); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if _, err := client.ReadFile("share", "A.txt"); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(server.dialAuth) != 2 {
		t.Fatalf("expected two dials, got %d", len(server.dialAuth))
	}
	reconnected := server.dialAuth[1]
	if reconnected.mode != AuthModeNTHash || reconnected.ntHash != auth.NTHash {
		t.Fatalf("reconnect did not preserve NT hash mode")
	}
	if reconnected.password != "" {
		t.Fatalf("NT hash reconnect must not introduce a password")
	}
}

// TestRepeatedResetExhaustsBoundedRetries is A17 case 2: repeated resets produce
// a bounded failure (original attempt + 2 reconnects) and never loop forever.
func TestRepeatedResetExhaustsBoundedRetries(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "B.docx", []byte("bravo"))
	for i := 0; i < 5; i++ {
		server.script(readKey("share", "B.docx"), opScript{err: resetError(), killTrunk: true})
	}
	client := newFaultyClient(t, server)

	_, err := client.ReadFile("share", "B.docx")
	if err == nil {
		t.Fatal("expected the read to fail after the retry budget was exhausted")
	}
	if !IsReconnectable(err) {
		t.Fatalf("expected a reconnectable error, got %v", err)
	}
	stats := client.TransportStats()
	if stats.ReconnectsAttempted != int64(maxReconnectAttempts) {
		t.Fatalf("reconnects=%d, want %d", stats.ReconnectsAttempted, maxReconnectAttempts)
	}
	if stats.RetryExhausted != 1 {
		t.Fatalf("expected one exhausted retry, got %#v", stats)
	}
	if server.dialCount() != 1+maxReconnectAttempts {
		t.Fatalf("dial count=%d, want %d", server.dialCount(), 1+maxReconnectAttempts)
	}
}

// TestMountRecoversFromReset is A17 case 3: a reset during tree connect is
// recovered by reconnecting and re-creating the tree.
func TestMountRecoversFromReset(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(mountKey("share"), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)

	data, err := client.ReadFile("share", "A.txt")
	if err != nil {
		t.Fatalf("read after mount reset failed: %v", err)
	}
	if string(data) != "alpha" {
		t.Fatalf("unexpected data %q", data)
	}
	if server.dialCount() != 2 {
		t.Fatalf("dial count=%d, want 2", server.dialCount())
	}
}

// TestDirectoryEnumerationRecoversFromReset is A17 case 4: a reset mid-walk
// restarts that directory on a fresh tree without losing entries.
func TestDirectoryEnumerationRecoversFromReset(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("a"))
	server.addFile("share", "B.txt", []byte("b"))
	server.addFile("share", "C.txt", []byte("c"))
	server.setDirEntries("share", "A.txt", "B.txt", "C.txt")
	server.script(dirKey("share", ""), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)

	var seen []string
	if err := client.WalkShareWithOptions("share", WalkOptions{}, func(file RemoteFile) error {
		if !file.IsDir {
			seen = append(seen, file.Name)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("enumerated %v, want all three entries after restart", seen)
	}
	stats := client.TransportStats()
	if stats.EnumerationFailures != 1 {
		t.Fatalf("expected one enumeration failure to be accounted, got %#v", stats)
	}
}

// TestPartialReadIsDiscardedAndReread is A17 case 5 and A7: bytes read before
// the reset are thrown away and the file is read again from the start.
func TestPartialReadIsDiscardedAndReread(t *testing.T) {
	server := newFakeServer()
	full := []byte("complete-file-content")
	server.addFile("share", "B.docx", full)
	server.script(readKey("share", "B.docx"), opScript{
		err:       resetError(),
		partial:   []byte("complete-"),
		killTrunk: true,
	})
	client := newFaultyClient(t, server)

	data, err := client.ReadFile("share", "B.docx")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(data) != string(full) {
		t.Fatalf("returned %q, want the complete re-read %q", data, full)
	}
}

// TestConcurrentWorkersShareOneReconnect is A17 case 6 and A10: many workers
// observing the same dead session must produce one coordinated reconnect.
func TestConcurrentWorkersShareOneReconnect(t *testing.T) {
	server := newFakeServer()
	const workers = 8
	for i := 0; i < workers; i++ {
		server.addFile("share", fmt.Sprintf("file-%d.txt", i), []byte(strings.Repeat("x", 32)))
	}
	// Kill the transport by making one file reset it before the workers start.
	server.script(readKey("share", "file-0.txt"), opScript{err: resetError(), killTrunk: true})

	client := newFaultyClient(t, server)

	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if _, err := client.ReadFile("share", fmt.Sprintf("file-%d.txt", index)); err != nil {
				failures.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d concurrent reads failed", failures.Load())
	}
	stats := client.TransportStats()
	if stats.ReconnectsAttempted != 1 {
		t.Fatalf("expected one coordinated reconnect, got %#v", stats)
	}
	if stats.ReconnectsSucceeded != 1 {
		t.Fatalf("expected the reconnect to succeed, got %#v", stats)
	}
}

// TestAccessDeniedDoesNotReconnect is A17 case 7.
func TestAccessDeniedDoesNotReconnect(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: deniedError()})
	client := newFaultyClient(t, server)

	_, err := client.ReadFile("share", "A.txt")
	if err == nil {
		t.Fatal("expected access denied")
	}
	stats := client.TransportStats()
	if stats.ReconnectsAttempted != 0 || stats.TransportFailures != 0 {
		t.Fatalf("access denied must not trigger reconnect: %#v", stats)
	}
	if server.dialCount() != 1 {
		t.Fatalf("dial count=%d, want only the initial connect", server.dialCount())
	}
}

// TestInvalidCredentialsDoesNotReconnectLoop is A17 case 8: repeated
// authentication failure is bounded and reported, never retried forever.
func TestInvalidCredentialsDoesNotReconnectLoop(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)
	// Every *reconnect* attempt fails authentication (the initial connect
	// already succeeded).
	for i := 0; i < 8; i++ {
		server.queueDialError(logonFailureError())
	}

	_, err := client.ReadFile("share", "A.txt")
	if err == nil {
		t.Fatal("expected the read to fail")
	}
	stats := client.TransportStats()
	if stats.ReconnectsFailed != 1 {
		t.Fatalf("expected exactly one failed reconnect, got %#v", stats)
	}
	if server.dialCount() > 2 {
		t.Fatalf("invalid credentials caused %d dial attempts", server.dialCount())
	}
}

// TestSecondShareStillWorksAfterReconnect is A11: a dead transport invalidates
// every tree, and shares mounted afterwards use the recovered session.
func TestSecondShareStillWorksAfterReconnect(t *testing.T) {
	server := newFakeServer()
	server.addFile("shareA", "A.txt", []byte("alpha"))
	server.addFile("shareB", "B.txt", []byte("bravo"))
	server.script(readKey("shareA", "A.txt"), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)

	if _, err := client.ReadFile("shareA", "A.txt"); err != nil {
		t.Fatalf("share A read failed: %v", err)
	}
	data, err := client.ReadFile("shareB", "B.txt")
	if err != nil {
		t.Fatalf("share B read failed after reconnect: %v", err)
	}
	if string(data) != "bravo" {
		t.Fatalf("unexpected share B data %q", data)
	}
}

// TestTransportEventsAreReported covers the structured logging contract.
func TestTransportEventsAreReported(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)

	var kinds []TransportEventKind
	client.SetTransportEventHandler(func(event TransportEvent) {
		kinds = append(kinds, event.Kind)
		if event.Server == "" {
			t.Errorf("transport event lost the server name")
		}
	})
	if _, err := client.ReadFile("share", "A.txt"); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(kinds) != 2 || kinds[0] != TransportEventRetrying || kinds[1] != TransportEventRestored {
		t.Fatalf("unexpected transport events: %v", kinds)
	}
}

// TestCredentialMaterialIsNotRendered guards against accidental logging of the
// operator credential context.
func TestCredentialMaterialIsNotRendered(t *testing.T) {
	client := NewClient()
	auth := resolvedAuth{mode: AuthModePassword, username: "operator", domain: "DOMAIN", password: "SuperSecret123!"}
	rendered := fmt.Sprintf("%v %#v %v %#v", auth, auth, client, client)
	if strings.Contains(rendered, "SuperSecret123!") {
		t.Fatalf("credential material was rendered: %s", rendered)
	}
}

// TestContextCancellationIsNotReconnectable keeps caller cancellation out of the
// reconnect path.
func TestContextCancellationIsNotReconnectable(t *testing.T) {
	if IsReconnectable(context.Canceled) || IsReconnectable(context.DeadlineExceeded) {
		t.Fatal("context cancellation must not be treated as a dead transport")
	}
	if !IsReconnectable(resetError()) {
		t.Fatal("transport reset must be reconnectable")
	}
	if IsReconnectable(deniedError()) || IsReconnectable(errors.New("access is denied")) {
		t.Fatal("access denied must never be reconnectable")
	}
}

// TestOperationFailuresAreReportedOnce covers the failure-reporting contract:
// one structured record per ultimately failed operation, with attempt and
// reconnect detail, and nothing at all for operations that recover.
func TestOperationFailuresAreReportedOnce(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "B.docx", []byte("bravo"))
	for i := 0; i < 5; i++ {
		server.script(readKey("share", "B.docx"), opScript{err: resetError(), killTrunk: true})
	}
	client := newFaultyClient(t, server)
	var reported []OperationFailure
	client.SetOperationFailureHandler(func(failure OperationFailure) {
		reported = append(reported, failure)
	})
	if _, err := client.ReadFile("share", "B.docx"); err == nil {
		t.Fatal("expected the read to fail")
	}
	if len(reported) != 1 {
		t.Fatalf("expected one final failure record, got %d: %#v", len(reported), reported)
	}
	failure := reported[0]
	if failure.Category != CategoryTransport {
		t.Errorf("category = %s, want %s", failure.Category, CategoryTransport)
	}
	if failure.AttemptsUsed() != totalOperationAttempts {
		t.Errorf("attempts = %d, want %d", failure.AttemptsUsed(), totalOperationAttempts)
	}
	if !failure.ReconnectAttempted {
		t.Error("reconnect attempt was not recorded")
	}
}

// TestRecoveredOperationsAreNotReportedAsFailures proves a retried read never
// reaches the failure report.
func TestRecoveredOperationsAreNotReportedAsFailures(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "B.docx", []byte("bravo"))
	server.script(readKey("share", "B.docx"), opScript{err: resetError(), killTrunk: true})
	client := newFaultyClient(t, server)
	reported := 0
	client.SetOperationFailureHandler(func(OperationFailure) { reported++ })
	if _, err := client.ReadFile("share", "B.docx"); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if reported != 0 {
		t.Fatalf("recovered operation was reported as a failure %d time(s)", reported)
	}
}

// TestAccessDeniedIsReportedWithoutReconnect covers the non-retryable category.
func TestAccessDeniedIsReportedWithoutReconnect(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.script(readKey("share", "A.txt"), opScript{err: deniedError()})
	client := newFaultyClient(t, server)
	var reported []OperationFailure
	client.SetOperationFailureHandler(func(failure OperationFailure) { reported = append(reported, failure) })
	if _, err := client.ReadFile("share", "A.txt"); err == nil {
		t.Fatal("expected access denied")
	}
	if len(reported) != 1 || reported[0].Category != CategoryAccessDenied {
		t.Fatalf("access denied was not categorized: %#v", reported)
	}
	if reported[0].ReconnectAttempted {
		t.Fatal("access denied must not attempt a reconnect")
	}
}

// TestDirectoryEnumerationFailureIsReportedWithDirectoryPath covers the
// distinct handling of a failed directory listing.
func TestDirectoryEnumerationFailureIsReportedWithDirectoryPath(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	server.setDirEntries("share", "A.txt")
	for i := 0; i < 5; i++ {
		server.script(dirKey("share", "Docs"), opScript{err: resetError(), killTrunk: true})
	}
	client := newFaultyClient(t, server)
	server.setDirEntries("share", "Docs")
	var reported []OperationFailure
	client.SetOperationFailureHandler(func(failure OperationFailure) { reported = append(reported, failure) })
	// The walk surfaces the failure to its caller; the failure report is what
	// this test validates.
	if err := client.WalkShareWithOptions("share", WalkOptions{}, func(RemoteFile) error { return nil }); err == nil {
		t.Fatal("expected the walk to report the enumeration failure")
	}
	if len(reported) != 1 {
		t.Fatalf("expected one enumeration failure, got %#v", reported)
	}
	if reported[0].Operation != "directory enumeration" || reported[0].Category != CategoryEnumeration {
		t.Fatalf("enumeration failure was not represented distinctly: %#v", reported[0])
	}
	if reported[0].Share != "share" {
		t.Fatalf("enumeration failure lost the share: %#v", reported[0])
	}
}

// TestMountFailureIsReported covers the tree-connect category.
func TestMountFailureIsReported(t *testing.T) {
	server := newFakeServer()
	server.addFile("share", "A.txt", []byte("alpha"))
	for i := 0; i < 5; i++ {
		server.script(mountKey("share"), opScript{err: resetError(), killTrunk: true})
	}
	client := newFaultyClient(t, server)
	var reported []OperationFailure
	client.SetOperationFailureHandler(func(failure OperationFailure) { reported = append(reported, failure) })
	if _, err := client.ReadFile("share", "A.txt"); err == nil {
		t.Fatal("expected the mount to fail")
	}
	if len(reported) != 1 {
		t.Fatalf("expected one failure record, got %#v", reported)
	}
	if reported[0].Category != CategoryTransport && reported[0].Category != CategoryMount {
		t.Fatalf("mount failure category = %s", reported[0].Category)
	}
}

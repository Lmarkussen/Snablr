package smb

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// stallGate models a server that accepts the connection and then stops
// answering. Blocked operations are released when the session is closed, which
// is what closing a real socket does, so no goroutine is retained.
type stallGate struct {
	ch   chan struct{}
	once sync.Once
}

func newStallGate() *stallGate { return &stallGate{ch: make(chan struct{})} }

func (g *stallGate) close() { g.once.Do(func() { close(g.ch) }) }

func (g *stallGate) wait() error {
	<-g.ch
	return net.ErrClosed
}

// stallingServer dials sessions whose selected operations wedge forever.
type stallingServer struct {
	mu          sync.Mutex
	dials       int
	mountStall  bool
	dirStall    bool
	statStall   bool
	openStall   bool
	readStall   bool
	readPartial []byte
	dirEntries  []fs.FileInfo
	files       map[string][]byte
}

func newStallingServer() *stallingServer {
	return &stallingServer{files: map[string][]byte{}}
}

func (s *stallingServer) Dial(context.Context, string, resolvedAuth, time.Duration, time.Duration) (transportSession, error) {
	s.mu.Lock()
	s.dials++
	s.mu.Unlock()
	return &stallingSession{server: s, gate: newStallGate()}, nil
}

func (s *stallingServer) dialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

// stallConfig snapshots the wedged-operation switches under the server lock.
// The client may now have a phase still in flight on its own goroutine when a
// caller gives up on it, so the fake must be safe for concurrent access.
func (s *stallingServer) stallConfig() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]bool{
		"mount": s.mountStall,
		"dir":   s.dirStall,
		"stat":  s.statStall,
		"open":  s.openStall,
		"read":  s.readStall,
	}
}

func (s *stallingServer) config(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch key {
	case "mount":
		return s.mountStall
	case "dir":
		return s.dirStall
	case "stat":
		return s.statStall
	case "open":
		return s.openStall
	case "read":
		return s.readStall
	default:
		return false
	}
}

func (s *stallingServer) entries() []fs.FileInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fs.FileInfo(nil), s.dirEntries...)
}

func (s *stallingServer) file(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.files[name]
	return content, ok
}

func (s *stallingServer) partial() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.readPartial...)
}

type stallingSession struct {
	server *stallingServer
	gate   *stallGate
}

func (s *stallingSession) Mount(string) (transportTree, error) {
	if s.server.config("mount") {
		return nil, s.gate.wait()
	}
	return &stallingTree{session: s}, nil
}

func (s *stallingSession) ListSharenames() ([]string, error) { return []string{"share"}, nil }

func (s *stallingSession) Close() error {
	s.gate.close()
	return nil
}

type stallingTree struct{ session *stallingSession }

func (t *stallingTree) ReadDir(string) ([]fs.FileInfo, error) {
	if t.session.server.config("dir") {
		return nil, t.session.gate.wait()
	}
	return t.session.server.entries(), nil
}

func (t *stallingTree) Stat(name string) (fs.FileInfo, error) {
	if t.session.server.config("stat") {
		return nil, t.session.gate.wait()
	}
	content, ok := t.session.server.file(name)
	if !ok {
		return nil, errors.New("not found")
	}
	return fakeFileInfo{name: name, size: int64(len(content))}, nil
}

func (t *stallingTree) Open(name string) (transportFile, error) {
	if t.session.server.config("open") {
		return nil, t.session.gate.wait()
	}
	content, ok := t.session.server.file(name)
	if !ok {
		return nil, errors.New("not found")
	}
	return &stallingFile{server: t.session.server, gate: t.session.gate, data: content}, nil
}

func (t *stallingTree) Umount() error                               { return nil }
func (t *stallingTree) MkdirAll(string, fs.FileMode) error          { return nil }
func (t *stallingTree) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (t *stallingTree) RemoveAll(string) error                      { return nil }

type stallingFile struct {
	server *stallingServer
	gate   *stallGate
	data   []byte
	sent   int
}

func (f *stallingFile) Read(p []byte) (int, error) {
	partial := f.server.partial()
	if f.sent < len(partial) {
		n := copy(p, partial[f.sent:])
		f.sent += n
		return n, nil
	}
	if f.server.config("read") {
		return 0, f.gate.wait()
	}
	if f.sent >= len(f.data) {
		return 0, nil
	}
	n := copy(p, f.data[f.sent:])
	f.sent += n
	return n, nil
}

func (f *stallingFile) Close() error { return nil }

// hangingDialer never completes a dial until its context is cancelled, which
// models a reconnect leader that cannot finish.
type hangingDialer struct {
	mu    sync.Mutex
	dials int
}

func (d *hangingDialer) Dial(ctx context.Context, _ string, _ resolvedAuth, _, _ time.Duration) (transportSession, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *hangingDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// shortTimeouts keeps the hang tests fast while exercising the same code paths.
func shortTimeouts(client *Client) {
	client.SetHandshakeTimeout(200 * time.Millisecond)
	client.SetOperationTimeout(250 * time.Millisecond)
	client.SetReadIdleTimeout(250 * time.Millisecond)
	client.SetReconnectWaitLimit(2 * time.Second)
	client.SetRecoveryBudget(3 * time.Second)
}

func hangClient(t *testing.T, dialer transportDialer) *Client {
	t.Helper()
	client := NewClient()
	client.dialer = dialer
	shortTimeouts(client)
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestBoundedTimingClassification pins the stable categories the failure model
// and metrics depend on.
func TestBoundedTimingClassification(t *testing.T) {
	timeout := &operationTimeoutError{Operation: "read A.txt on share", Limit: 30 * time.Second}
	if !errors.Is(timeout, ErrOperationTimeout) {
		t.Fatal("timeout error does not unwrap to ErrOperationTimeout")
	}
	if CategorizeError(timeout) != CategoryTimeout {
		t.Fatalf("timeout category = %q, want %q", CategorizeError(timeout), CategoryTimeout)
	}
	if !IsReconnectable(timeout) {
		t.Fatal("timeout must require a reconnect because the framing state is unknown")
	}
	if !isRetryableOperation(timeout) {
		t.Fatal("timeout must be retryable within the recovery budget")
	}

	auth := logonFailureError()
	if !IsAuthFailure(auth) {
		t.Fatal("logon failure was not classified as an authentication failure")
	}
	if CategorizeError(auth) != CategoryAuthFailure {
		t.Fatalf("auth category = %q, want %q", CategorizeError(auth), CategoryAuthFailure)
	}
	if IsReconnectable(auth) {
		t.Fatal("authentication failures must never trigger a reconnect")
	}
	if isRetryableOperation(auth) {
		t.Fatal("authentication failures must never be retried")
	}

	if IsAuthFailure(context.Canceled) || IsReconnectable(context.Canceled) {
		t.Fatal("cancellation must not be treated as an auth or transport failure")
	}
}

// TestTreeConnectHangIsBounded covers a tree connect that never answers.
func TestTreeConnectHangIsBounded(t *testing.T) {
	server := newStallingServer()
	server.mountStall = true
	client := hangClient(t, server)

	start := time.Now()
	if _, err := client.ReadFile("share", "A.txt"); err == nil {
		t.Fatal("expected the wedged tree connect to fail")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("tree connect was not bounded: %s", elapsed)
	}
	if client.TransportStats().OperationTimeouts == 0 {
		t.Fatal("tree connect timeout was not recorded")
	}
}

// TestDirectoryEnumerationHangIsBounded covers a directory listing that never
// answers. The walk must fail closed rather than block the caller.
func TestDirectoryEnumerationHangIsBounded(t *testing.T) {
	server := newStallingServer()
	server.dirStall = true
	client := hangClient(t, server)

	start := time.Now()
	err := client.WalkShareWithOptions("share", WalkOptions{}, func(RemoteFile) error { return nil })
	if err == nil {
		t.Fatal("expected the wedged directory enumeration to fail")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("directory enumeration was not bounded: %s", elapsed)
	}
	if client.TransportStats().OperationTimeouts == 0 {
		t.Fatal("enumeration timeout was not recorded")
	}
}

// TestOpenHangIsBounded covers a file open that never answers.
func TestOpenHangIsBounded(t *testing.T) {
	server := newStallingServer()
	server.openStall = true
	// The file must exist so stat succeeds and the wedged open is actually
	// reached; otherwise the read fails early and the test proves nothing.
	server.files["A.txt"] = []byte("alpha")
	client := hangClient(t, server)

	start := time.Now()
	data, err := client.ReadFile("share", "A.txt")
	if err == nil {
		t.Fatal("expected the wedged open to fail")
	}
	if len(data) != 0 {
		t.Fatalf("a wedged open returned data: %d bytes", len(data))
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("open was not bounded: %s", elapsed)
	}
	if client.TransportStats().OperationTimeouts == 0 {
		t.Fatal("open timeout was not recorded")
	}
}

// TestStatHangIsBounded covers a stat that never answers.
func TestStatHangIsBounded(t *testing.T) {
	server := newStallingServer()
	server.statStall = true
	server.files["A.txt"] = []byte("alpha")
	client := hangClient(t, server)

	start := time.Now()
	if _, err := client.ReadFile("share", "A.txt"); err == nil {
		t.Fatal("expected the wedged stat to fail")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("stat was not bounded: %s", elapsed)
	}
}

// TestPartialReadStallIsDiscarded covers a read that delivers some bytes and
// then wedges: the attempt is abandoned, partial bytes are discarded, and the
// operation still terminates inside its budget.
func TestPartialReadStallIsDiscarded(t *testing.T) {
	server := newStallingServer()
	server.readStall = true
	server.readPartial = []byte("partial-bytes")
	server.files["A.txt"] = []byte("partial-bytes-never-completed")
	client := hangClient(t, server)

	start := time.Now()
	data, err := client.ReadFile("share", "A.txt")
	if err == nil {
		t.Fatalf("expected the stalled read to fail, got %d bytes", len(data))
	}
	if len(data) != 0 {
		t.Fatalf("partial bytes leaked to the caller: %d bytes", len(data))
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("stalled read was not bounded: %s", elapsed)
	}
}

// TestReconnectLeaderTimeoutReleasesWaiters covers a reconnect leader that
// cannot finish. Every waiting worker must be released.
func TestReconnectLeaderTimeoutReleasesWaiters(t *testing.T) {
	dialer := &hangingDialer{}
	client := NewClient()
	client.dialer = dialer
	shortTimeouts(client)
	// Seed a credential context without a live session: the first reader
	// becomes the reconnect leader and cannot finish.
	client.mu.Lock()
	client.host = "fileserver.example.test"
	client.serverName = "fileserver.example.test"
	client.dialAddr = "fileserver.example.test:445"
	client.auth = resolvedAuth{mode: AuthModePassword, username: "operator"}
	client.session = nil
	client.mu.Unlock()

	const workers = 8
	var wg sync.WaitGroup
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.ReadFile("share", "A.txt")
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatal("waiters were not released after the reconnect leader timed out")
	}
	if dialer.dialCount() == 0 {
		t.Fatal("no reconnect was attempted")
	}
}

// TestConcurrentWorkersOnWedgedServerShareOneReconnectChain proves a wedged
// server produces one reconnect chain rather than one per worker.
func TestConcurrentWorkersOnWedgedServerShareOneReconnectChain(t *testing.T) {
	server := newStallingServer()
	server.mountStall = true
	client := hangClient(t, server)

	// Start every worker at the same instant so the coordination path is
	// exercised deterministically: one leader per recovery round.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for index := 0; index < 8; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = client.ReadFile("share", "A.txt")
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatal("workers were not released")
	}
	// Initial connect plus one dial per coordinated recovery round. With eight
	// workers and a bounded retry budget that is a handful of dials, never one
	// per worker.
	if dials := server.dialCount(); dials >= 8 {
		t.Fatalf("reconnect storm detected: %d dials for 8 workers on one wedged server", dials)
	}
}

// TestUnreachableHostFailsFast covers a TCP endpoint that refuses connections.
func TestUnreachableHostFailsFast(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	client := NewClient()
	client.SetHandshakeTimeout(200 * time.Millisecond)
	start := time.Now()
	if _, err := client.dialBounded(context.Background(), addr, resolvedAuth{mode: AuthModePassword, username: "operator"}); err == nil {
		t.Fatal("expected dial to an unreachable endpoint to fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("unreachable host was not bounded: %s", elapsed)
	}
}

// TestBlackholeNegotiationIsBounded covers a TCP endpoint that accepts the
// connection and then never answers SMB negotiate.
func TestBlackholeNegotiationIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	held := make(chan net.Conn, 1)
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		held <- conn
		<-release
		_ = conn.Close()
	}()

	start := time.Now()
	_, dialErr := (smb2Dialer{}).Dial(context.Background(), listener.Addr().String(),
		resolvedAuth{mode: AuthModePassword, username: "operator"}, time.Second, 300*time.Millisecond)
	elapsed := time.Since(start)
	if dialErr == nil {
		t.Fatal("expected the blackholed handshake to fail")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("handshake was not bounded: %s", elapsed)
	}
}

// TestAuthFailureDoesNotReconnect covers an explicit logon failure: it must be
// terminal, with no reconnect attempts at all.
func TestAuthFailureDoesNotReconnect(t *testing.T) {
	server := newFakeServer()
	server.queueDialError(logonFailureError())
	client := NewClient()
	client.dialer = server
	shortTimeouts(client)

	err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Wrong-1!"))
	if err == nil {
		t.Fatal("expected the connect to fail")
	}
	if !IsAuthFailure(err) {
		t.Fatalf("logon failure was not classified as terminal: %v", err)
	}
	stats := client.TransportStats()
	if stats.ReconnectsAttempted != 0 {
		t.Fatalf("auth failure triggered reconnects: %#v", stats)
	}
	if stats.AuthFailures == 0 {
		t.Fatalf("auth failure was not counted: %#v", stats)
	}
}

// TestCancellationDuringReconnectReleasesEverything covers context
// cancellation while a reconnect is in flight.
func TestCancellationDuringReconnectReleasesEverything(t *testing.T) {
	dialer := &hangingDialer{}
	client := NewClient()
	client.dialer = dialer
	shortTimeouts(client)
	client.mu.Lock()
	client.host = "fileserver.example.test"
	client.serverName = "fileserver.example.test"
	client.dialAddr = "fileserver.example.test:445"
	client.auth = resolvedAuth{mode: AuthModePassword, username: "operator"}
	client.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for index := 0; index < 4; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.ReadFileContext(ctx, "share", "A.txt")
		}()
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("cancellation did not release the workers")
	}
}

// TestHungShareDoesNotBlockHealthyShare walks a wedged share and then a healthy
// one, proving one bad share cannot freeze the rest of the target.
func TestHungShareDoesNotBlockHealthyShare(t *testing.T) {
	server := newStallingServer()
	server.dirStall = true
	client := hangClient(t, server)

	badStart := time.Now()
	if err := client.WalkShareWithOptions("bad-share", WalkOptions{}, func(RemoteFile) error { return nil }); err == nil {
		t.Fatal("expected the wedged share to fail")
	}
	if elapsed := time.Since(badStart); elapsed > 30*time.Second {
		t.Fatalf("wedged share was not bounded: %s", elapsed)
	}

	server.mu.Lock()
	server.dirStall = false
	server.dirEntries = []fs.FileInfo{fakeFileInfo{name: "A.txt", size: 5}}
	server.files["A.txt"] = []byte("alpha")
	server.mu.Unlock()

	healthyStart := time.Now()
	seen := 0
	if err := client.WalkShareWithOptions("healthy-share", WalkOptions{}, func(RemoteFile) error {
		seen++
		return nil
	}); err != nil {
		t.Fatalf("healthy share failed: %v", err)
	}
	if seen == 0 {
		t.Fatal("healthy share produced no entries")
	}
	if elapsed := time.Since(healthyStart); elapsed > 30*time.Second {
		t.Fatalf("healthy share was not bounded: %s", elapsed)
	}
}

// TestNoGoroutineGrowthAfterTimeouts proves repeated stall cycles release every
// blocked call instead of retaining goroutines.
func TestNoGoroutineGrowthAfterTimeouts(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for cycle := 0; cycle < 5; cycle++ {
		server := newStallingServer()
		server.mountStall = true
		client := NewClient()
		client.dialer = server
		shortTimeouts(client)
		if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ReadFile("share", "A.txt"); err == nil {
			t.Fatal("expected the wedged server to fail")
		}
		_ = client.Close()
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		current := runtime.NumGoroutine()
		if current <= baseline+8 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines retained after stall cycles: baseline=%d current=%d", baseline, current)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

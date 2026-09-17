package smb

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests pin the recall property of transport containment: work withheld
// from an unwell share must resume once the transport recovers, so readable
// files that follow a transient fault are still content-read. They also pin the
// opposite property: a share that never recovers must still be abandoned
// promptly and must not take the rest of the target with it.

// scriptedShareServer is a one-share SMB server whose reads can be degraded for
// a bounded window or wedged per path. Everything heals, which models a
// transient transport problem rather than a permanently broken server.
type scriptedShareServer struct {
	mu sync.Mutex

	names    []string
	content  map[string][]byte
	stalls   map[string]int
	readOK   int
	attempts int
	dials    int

	// degradeAfterOK starts a window in which every read wedges once this many
	// reads have succeeded; the window then ends and reads work again.
	degradeAfterOK int
	degradeFor     time.Duration
	degradeAt      time.Time
}

func newScriptedShareServer() *scriptedShareServer {
	return &scriptedShareServer{
		content: map[string][]byte{},
		stalls:  map[string]int{},
	}
}

func (s *scriptedShareServer) add(name, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
	s.content[name] = []byte(body)
}

func (s *scriptedShareServer) store() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.content))
	for k, v := range s.content {
		out[k] = v
	}
	return out
}

func (s *scriptedShareServer) counters() (attempts, ok int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts, s.readOK
}

func (s *scriptedShareServer) degraded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degradeFor <= 0 {
		return false
	}
	if s.degradeAt.IsZero() {
		if s.degradeAfterOK <= 0 || s.readOK < s.degradeAfterOK {
			return false
		}
		s.degradeAt = time.Now()
	}
	return time.Since(s.degradeAt) < s.degradeFor
}

func (s *scriptedShareServer) Dial(context.Context, string, resolvedAuth, time.Duration, time.Duration) (transportSession, error) {
	s.mu.Lock()
	s.dials++
	s.mu.Unlock()
	return &scriptedSession{srv: s, gate: newStallGate()}, nil
}

type scriptedSession struct {
	srv  *scriptedShareServer
	gate *stallGate
}

func (s *scriptedSession) Mount(string) (transportTree, error) { return &scriptedTree{sess: s}, nil }
func (s *scriptedSession) ListSharenames() ([]string, error)   { return []string{"share"}, nil }
func (s *scriptedSession) Close() error                        { s.gate.close(); return nil }

type scriptedTree struct{ sess *scriptedSession }

func (t *scriptedTree) ReadDir(string) ([]fs.FileInfo, error) {
	t.sess.srv.mu.Lock()
	names := append([]string(nil), t.sess.srv.names...)
	sizes := make([]int, len(names))
	for i, name := range names {
		sizes[i] = len(t.sess.srv.content[name])
	}
	t.sess.srv.mu.Unlock()
	infos := make([]fs.FileInfo, 0, len(names))
	for i, name := range names {
		infos = append(infos, fakeFileInfo{name: name, size: int64(sizes[i])})
	}
	return infos, nil
}

func (t *scriptedTree) Stat(name string) (fs.FileInfo, error) {
	name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
	t.sess.srv.mu.Lock()
	body, ok := t.sess.srv.content[name]
	t.sess.srv.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return fakeFileInfo{name: name, size: int64(len(body))}, nil
}

func (t *scriptedTree) Open(name string) (transportFile, error) {
	name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
	srv := t.sess.srv
	if srv.degraded() {
		srv.mu.Lock()
		srv.attempts++
		srv.mu.Unlock()
		return &scriptedFile{sess: t.sess, wedge: true}, nil
	}
	srv.mu.Lock()
	srv.attempts++
	body, ok := srv.content[name]
	wedge := srv.stalls[name] > 0
	if wedge {
		srv.stalls[name]--
	}
	srv.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &scriptedFile{sess: t.sess, body: body, wedge: wedge}, nil
}

func (t *scriptedTree) Umount() error                               { return nil }
func (t *scriptedTree) MkdirAll(string, fs.FileMode) error          { return nil }
func (t *scriptedTree) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (t *scriptedTree) RemoveAll(string) error                      { return nil }

type scriptedFile struct {
	sess  *scriptedSession
	body  []byte
	wedge bool
	sent  int
}

func (f *scriptedFile) Read(p []byte) (int, error) {
	if f.wedge || f.sess.srv.degraded() {
		// Block until the watchdog closes the session, exactly like a stalled
		// socket read against a hung server.
		if err := f.sess.gate.wait(); err != nil {
			return 0, err
		}
		return 0, net.ErrClosed
	}
	if f.sent >= len(f.body) {
		f.sess.srv.mu.Lock()
		f.sess.srv.readOK++
		f.sess.srv.mu.Unlock()
		return 0, nil
	}
	n := copy(p, f.body[f.sent:])
	f.sent += n
	return n, nil
}

func (f *scriptedFile) Close() error { return nil }

// recallTimeouts scales every bound down so the tests stay fast while keeping
// the production ordering of the phases.
func recallTimeouts(client *Client) {
	client.SetHandshakeTimeout(150 * time.Millisecond)
	client.SetOperationTimeout(200 * time.Millisecond)
	client.SetReadIdleTimeout(150 * time.Millisecond)
	client.SetReadTotalTimeout(3 * time.Second)
	client.SetReconnectWaitLimit(300 * time.Millisecond)
	client.SetRecoveryBudget(2 * time.Second)
	client.SetShareProbeCooldown(100 * time.Millisecond)
	client.SetShareRecoveryBudget(1500 * time.Millisecond)
	client.SetTargetRecoveryBudget(time.Hour)
}

func recallTestClient(t *testing.T, srv *scriptedShareServer) *Client {
	t.Helper()
	client := NewClient()
	client.dialer = srv
	recallTimeouts(client)
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// scanShareMirroringApp walks one share into a worker pool shaped like
// app.scanHost: a buffered jobs channel drained by the configured worker count,
// with the walker backpressured by that channel and completion waiting for
// every queued job.
func scanShareMirroringApp(t *testing.T, client *Client, share string, workers int) (read map[string]bool, failed map[string]error, enumerated []string, walkErr error) {
	t.Helper()
	type job struct{ path string }
	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup
	read = map[string]bool{}
	failed = map[string]error{}
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				_, err := client.ReadFile(share, item.path)
				key := strings.TrimPrefix(strings.ReplaceAll(item.path, `\`, "/"), "/")
				mu.Lock()
				if err == nil {
					read[key] = true
				} else {
					failed[key] = err
				}
				mu.Unlock()
			}
		}()
	}
	walkErr = client.WalkShareWithOptions(share, WalkOptions{}, func(rf RemoteFile) error {
		if rf.IsDir {
			return nil
		}
		enumerated = append(enumerated, strings.TrimPrefix(rf.Path, "/"))
		jobs <- job{path: strings.ReplaceAll(rf.Path, "/", `\`)}
		return nil
	})
	close(jobs)
	wg.Wait()
	return read, failed, enumerated, walkErr
}

func requireRead(t *testing.T, read map[string]bool, failed map[string]error, name string) {
	t.Helper()
	if read[name] {
		return
	}
	if err, ok := failed[name]; ok {
		t.Fatalf("control file %s was not content-read after recovery: %v", name, err)
	}
	t.Fatalf("control file %s was never attempted", name)
}

// TestRecallSurvivesTransientTransportWindow is the core recall regression: a
// share that is briefly unwell must not permanently lose the readable files
// that follow the fault window.
func TestRecallSurvivesTransientTransportWindow(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 1; i <= 200; i++ {
		srv.add(fmt.Sprintf("file%03d.txt", i), "nothing interesting here")
	}
	srv.add("settings.ini", "AdminPassword=Synthetic-Early-123!")
	srv.add("config.ini", "AdminPassword=Synthetic-Admin-123!")
	srv.add("OperationsGuide.docx", "Passordet er; Synthetic-Docx-123!")
	srv.add("notes.txt", "Password=Synthetic-Txt-123!")
	// Every read wedges for a bounded window starting after 60 successful
	// reads, then the transport is healthy again.
	srv.degradeAfterOK = 60
	srv.degradeFor = 700 * time.Millisecond

	client := recallTestClient(t, srv)
	read, failed, enumerated, walkErr := scanShareMirroringApp(t, client, "share", 15)
	if walkErr != nil {
		t.Fatalf("share walk failed after a recoverable transport window: %v", walkErr)
	}
	if len(enumerated) != 204 {
		t.Fatalf("share walk stopped early: enumerated %d of 204 objects", len(enumerated))
	}
	for _, control := range []string{"config.ini", "OperationsGuide.docx", "notes.txt"} {
		requireRead(t, read, failed, control)
	}
	stats := client.TransportStats()
	if stats.SharesWithheld == 0 {
		t.Fatal("a transport window that cost phase timeouts did not withhold the share")
	}
	if stats.SharesAbandoned != 0 {
		t.Fatalf("a recoverable transport window abandoned the share: %#v", stats)
	}
	if stats.OperationsResumed == 0 {
		t.Fatal("no operation was recorded as resumed after containment")
	}
}

// TestRecallResumesAfterBoundedStall pins the probe protocol: a few wedged
// operations withhold the share, and the next readable file restores it.
func TestRecallResumesAfterBoundedStall(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("stall%02d.ini", i)
		srv.add(name, "Password=Synthetic-Stall-123!")
		srv.stalls[name] = 99
	}
	srv.add("config.ini", "AdminPassword=Synthetic-Admin-123!")
	client := recallTestClient(t, srv)

	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("stall%02d.ini", i)
		if _, err := client.ReadFile("share", name); err == nil {
			t.Fatalf("%s unexpectedly read successfully", name)
		}
	}
	if _, targetUnhealthy, _ := client.healthSnapshot(); targetUnhealthy {
		t.Fatal("a single unwell share must not abandon the target")
	}
	data, err := client.ReadFile("share", "config.ini")
	if err != nil {
		t.Fatalf("readable file after a recoverable stall was not read: %v", err)
	}
	if string(data) != "AdminPassword=Synthetic-Admin-123!" {
		t.Fatalf("unexpected content: %q", data)
	}
}

// TestPermanentlyDeadShareStaysBounded proves recovery does not reintroduce
// pathological runtime: a share that never answers is abandoned within its
// recovery budget and the queued work fails fast instead of timing out each.
func TestPermanentlyDeadShareStaysBounded(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 1; i <= 2000; i++ {
		srv.add(fmt.Sprintf("file%04d.txt", i), "nothing")
	}
	srv.degradeAfterOK = 1
	srv.degradeFor = time.Hour
	client := recallTestClient(t, srv)
	client.SetShareProbeCooldown(50 * time.Millisecond)
	client.SetShareRecoveryBudget(600 * time.Millisecond)

	start := time.Now()
	read, _, _, walkErr := scanShareMirroringApp(t, client, "share", 15)
	elapsed := time.Since(start)
	if walkErr == nil {
		t.Fatal("a permanently dead share should be abandoned")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("permanently dead share was not bounded: %s", elapsed)
	}
	attempts, _ := srv.counters()
	// Only the first wave plus the bounded probes may touch a dead share;
	// thousands of queued files must not each pay a timeout.
	if attempts > 100 {
		t.Fatalf("dead share still attempted too many reads: %d", attempts)
	}
	if read["file0001.txt"] {
		t.Fatal("a dead share reported a successful read")
	}
	stats := client.TransportStats()
	if stats.SharesAbandoned == 0 {
		t.Fatalf("abandoned share was not counted for coverage: %#v", stats)
	}
	if stats.OperationsFastFailed == 0 {
		t.Fatalf("contained work was not counted as fast-failed: %#v", stats)
	}
}

// TestRecallOneDegradedShareDoesNotAbandonTarget proves the target-level rule
// needs more than one unwell share before the rest of the target is lost.
func TestRecallOneDegradedShareDoesNotAbandonTarget(t *testing.T) {
	srv := newScriptedShareServer()
	for i := 1; i <= 200; i++ {
		srv.add(fmt.Sprintf("bad%03d.txt", i), "nothing")
	}
	srv.degradeAfterOK = 1
	srv.degradeFor = 4 * time.Second

	client := recallTestClient(t, srv)
	client.SetTargetRecoveryBudget(600 * time.Millisecond)

	_, _, _, _ = scanShareMirroringApp(t, client, "bad", 15)
	if _, targetUnhealthy, _ := client.healthSnapshot(); targetUnhealthy {
		t.Fatal("one unwell share abandoned the whole target")
	}
}

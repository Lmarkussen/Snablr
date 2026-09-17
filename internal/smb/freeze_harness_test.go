package smb

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/officefixture"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

// Live-like share-freeze harness.
//
// The earlier recovery tests model every stall as a call that the session close
// path releases: their tree and file operations block on a gate that the
// session's Close closes. That is true for a plain socket read, but not for
// every blocking call inside the SMB dependency. go-smb2's credit account is the
// clearest example: before a request reaches the socket it calls account.loan,
// which waits on a channel that only an arriving response can feed, using the
// session context that DialContext fixed to context.Background(). Closing the
// socket, invalidating the session and cancelling the caller's context cannot
// release that wait, and the session close path itself contends for the
// transport mutex the wedged call holds.
//
// This harness models that class of fault directly: a wedged call is not
// released by the session close path. It reproduces the live symptom (workers
// held inside one share's transport calls, the bounded job queue filling, the
// share walker blocked mid-walk, later shares never starting) and asserts that
// the scanner still terminates inside its share recovery policy.

// harnessWedgeTTL is only a backstop so a deliberately wedged call eventually
// gives up if a test forgets to release it. Every test releases its wedges after
// the scan returns; the TTL is far longer than any assertion so a scanner that
// depended on the call returning would still be caught.
const harnessWedgeTTL = 30 * time.Second

var errHarnessWedge = errors.New("synthetic wedged transport call released")

// harnessWedge is a blocking transport call that only the harness can release.
// Session close does not release it.
type harnessWedge struct {
	release chan struct{}
	once    sync.Once
	ttl     time.Duration
}

func newHarnessWedge(ttl time.Duration) *harnessWedge {
	return &harnessWedge{release: make(chan struct{}), ttl: ttl}
}

func (w *harnessWedge) wait() error {
	timer := time.NewTimer(w.ttl)
	defer timer.Stop()
	select {
	case <-w.release:
		return errHarnessWedge
	case <-timer.C:
		return fmt.Errorf("%w: harness ttl", errHarnessWedge)
	}
}

func (w *harnessWedge) active() bool {
	if w == nil {
		return false
	}
	select {
	case <-w.release:
		return false
	default:
		return true
	}
}

func (w *harnessWedge) releaseAll() {
	if w == nil {
		return
	}
	w.once.Do(func() { close(w.release) })
}

// freezeServer is a synthetic SMB target with healthy shares and one share
// whose filesystem calls can be wedged.
type freezeServer struct {
	mu     sync.Mutex
	order  []string
	shares map[string]*freezeShare

	// wedgeShare names the share whose file operations currently wedge.
	wedgeShare string
	wedge      *harnessWedge

	// umountGate and logoffGate wedge cleanup calls independently of the share
	// wedge so cleanup stalls can be tested on an otherwise healthy target.
	umountGate      *harnessWedge
	umountFirstOnly atomic.Bool
	logoffGate      *harnessWedge

	dials         atomic.Int64
	wedgedOps     atomic.Int64
	umounts       atomic.Int64
	umountStalled atomic.Int64
	closes        atomic.Int64
}

type freezeShare struct {
	names   []string
	content map[string][]byte
}

func newFreezeServer() *freezeServer {
	return &freezeServer{shares: map[string]*freezeShare{}}
}

func (s *freezeServer) addShare(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.shares[name]; ok {
		return
	}
	s.shares[name] = &freezeShare{content: map[string][]byte{}}
	s.order = append(s.order, name)
	sort.Strings(s.order)
}

func (s *freezeServer) addFile(share, name, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.shares[share]
	if st == nil {
		st = &freezeShare{content: map[string][]byte{}}
		s.shares[share] = st
		s.order = append(s.order, share)
		sort.Strings(s.order)
	}
	st.names = append(st.names, name)
	st.content[name] = []byte(body)
}

func (s *freezeServer) fileCount(share string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.shares[share]; st != nil {
		return len(st.names)
	}
	return 0
}

// wedgeShareName marks one share whose file operations block until healShare or
// releaseAll is called. The wedge is deliberately not tied to the session.
func (s *freezeServer) wedgeShareName(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wedge != nil {
		s.wedge.releaseAll()
	}
	s.wedgeShare = name
	s.wedge = newHarnessWedge(harnessWedgeTTL)
}

func (s *freezeServer) healShare(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wedgeShare != name {
		return
	}
	s.wedge.releaseAll()
	s.wedge = nil
	s.wedgeShare = ""
}

func (s *freezeServer) stallUmount(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.umountGate = newHarnessWedge(ttl)
}

// stallFirstUmount wedges only the first tree disconnect, so one stalled
// cleanup cannot be confused with a server that can never disconnect a tree.
func (s *freezeServer) stallFirstUmount(ttl time.Duration) {
	s.stallUmount(ttl)
	s.umountFirstOnly.Store(true)
}

func (s *freezeServer) stallLogoff(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logoffGate = newHarnessWedge(ttl)
}

func (s *freezeServer) releaseAll() {
	s.mu.Lock()
	wedge, umount, logoff := s.wedge, s.umountGate, s.logoffGate
	s.mu.Unlock()
	wedge.releaseAll()
	umount.releaseAll()
	logoff.releaseAll()
}

func (s *freezeServer) currentWedge() *harnessWedge {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wedge
}

func (s *freezeServer) shareWedge(share string) *harnessWedge {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wedgeShare != share {
		return nil
	}
	return s.wedge
}

func (s *freezeServer) cleanupGates() (*harnessWedge, *harnessWedge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.umountGate, s.logoffGate
}

func (s *freezeServer) Dial(context.Context, string, resolvedAuth, time.Duration, time.Duration) (transportSession, error) {
	s.dials.Add(1)
	return &freezeSession{srv: s}, nil
}

type freezeSession struct{ srv *freezeServer }

func (s *freezeSession) Mount(mountPath string) (transportTree, error) {
	share := path.Base(strings.ReplaceAll(mountPath, `\`, "/"))
	s.srv.mu.Lock()
	_, ok := s.srv.shares[share]
	s.srv.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &freezeTree{srv: s.srv, share: share}, nil
}

func (s *freezeSession) ListSharenames() ([]string, error) {
	s.srv.mu.Lock()
	defer s.srv.mu.Unlock()
	return append([]string(nil), s.srv.order...), nil
}

// Close models the dependency's close path: the logoff request needs the same
// transport mutex a wedged call holds, so closing a session with a wedged
// operation is itself blocked until that operation is released.
func (s *freezeSession) Close() error {
	s.srv.closes.Add(1)
	if gate := s.srv.currentWedge(); gate.active() {
		return gate.wait()
	}
	umount, logoff := s.srv.cleanupGates()
	if logoff.active() {
		return logoff.wait()
	}
	if umount.active() {
		return umount.wait()
	}
	return nil
}

type freezeTree struct {
	srv   *freezeServer
	share string
}

// ReadDir answers even while the share is wedged: the live failure reached the
// share and enumerated it, then every file read stalled.
func (t *freezeTree) ReadDir(string) ([]fs.FileInfo, error) {
	t.srv.mu.Lock()
	st := t.srv.shares[t.share]
	names := append([]string(nil), st.names...)
	sizes := make([]int, len(names))
	for i, name := range names {
		sizes[i] = len(st.content[name])
	}
	t.srv.mu.Unlock()
	infos := make([]fs.FileInfo, 0, len(names))
	for i, name := range names {
		infos = append(infos, fakeFileInfo{name: name, size: int64(sizes[i])})
	}
	return infos, nil
}

func (t *freezeTree) Stat(name string) (fs.FileInfo, error) {
	if gate := t.srv.shareWedge(t.share); gate.active() {
		t.srv.wedgedOps.Add(1)
		return nil, gate.wait()
	}
	name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
	t.srv.mu.Lock()
	body, ok := t.srv.shares[t.share].content[name]
	t.srv.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeFileInfo{name: name, size: int64(len(body))}, nil
}

func (t *freezeTree) Open(name string) (transportFile, error) {
	if gate := t.srv.shareWedge(t.share); gate.active() {
		t.srv.wedgedOps.Add(1)
		return nil, gate.wait()
	}
	name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
	t.srv.mu.Lock()
	body, ok := t.srv.shares[t.share].content[name]
	t.srv.mu.Unlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &freezeFile{srv: t.srv, share: t.share, body: body}, nil
}

func (t *freezeTree) Umount() error {
	t.srv.umounts.Add(1)
	if gate, _ := t.srv.cleanupGates(); gate.active() {
		if t.srv.umountFirstOnly.Load() && t.srv.umountStalled.Add(1) > 1 {
			return nil
		}
		return gate.wait()
	}
	return nil
}

func (t *freezeTree) MkdirAll(string, fs.FileMode) error          { return nil }
func (t *freezeTree) WriteFile(string, []byte, fs.FileMode) error { return nil }
func (t *freezeTree) RemoveAll(string) error                      { return nil }

type freezeFile struct {
	srv   *freezeServer
	share string
	body  []byte
	off   int
}

func (f *freezeFile) Read(p []byte) (int, error) {
	if gate := f.srv.shareWedge(f.share); gate.active() {
		return 0, gate.wait()
	}
	if f.off >= len(f.body) {
		return 0, nil
	}
	n := copy(p, f.body[f.off:])
	f.off += n
	return n, nil
}

func (f *freezeFile) Close() error { return nil }

// freezeSink records what the real engine reported, so a control file can be
// told apart from a merely enumerated one.
type freezeSink struct {
	mu         sync.Mutex
	findings   []scanner.Finding
	candidates []credentialanalysis.Candidate
	readFiles  map[string]bool
	shares     []string
	shareAt    map[string]time.Time
	readErrs   int
	shareSeen  map[string]int
}

func newFreezeSink() *freezeSink {
	return &freezeSink{shareAt: map[string]time.Time{}, shareSeen: map[string]int{}, readFiles: map[string]bool{}}
}

func (s *freezeSink) WriteFinding(f scanner.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, f)
	return nil
}

func (s *freezeSink) Close() error { return nil }

// RecordCredentialCandidate captures credentials the engine reports through the
// credential-candidate path (for example a plain-language DOCX value).
func (s *freezeSink) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append(s.candidates, candidate)
	return nil
}

func (s *freezeSink) RecordHost(string) {}

func (s *freezeSink) RecordShare(_, share string) { s.markShare(share) }

func (s *freezeSink) markShare(share string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shares = append(s.shares, share)
	s.shareSeen[share]++
	if _, ok := s.shareAt[share]; !ok {
		s.shareAt[share] = time.Now()
	}
}

func (s *freezeSink) RecordFile(scanner.FileMetadata) {}

func (s *freezeSink) RecordSkip(scanner.FileMetadata, string) {}

func (s *freezeSink) RecordReadError(scanner.FileMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readErrs++
}

func (s *freezeSink) shareStarted(share string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.shareAt[share]
	return at, ok
}

func (s *freezeSink) sharesStarted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.shares...)
}

func (s *freezeSink) findingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.findings)
}

// recordRead records one file that was successfully content-read. This is the
// transport-level recall evidence, independent of which parser reported it.
func (s *freezeSink) recordRead(share, filePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readFiles[share+"|"+strings.TrimPrefix(strings.ReplaceAll(filePath, `\`, "/"), "/")] = true
}

func (s *freezeSink) readOK(share, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readFiles[share+"|"+name]
}

func (s *freezeSink) contentFinding(name, value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, finding := range s.findings {
		if !strings.Contains(strings.ReplaceAll(finding.FilePath, `\`, "/"), name) {
			continue
		}
		haystack := strings.Join([]string{
			finding.Match,
			finding.MatchedText,
			finding.MatchedTextRedacted,
			finding.Snippet,
			finding.Context,
			finding.ContextRedacted,
			finding.MatchReason,
		}, "\n")
		if strings.Contains(haystack, value) {
			return true
		}
	}
	for _, candidate := range s.candidates {
		haystack := strings.Join([]string{candidate.Value, candidate.Identity, candidate.Source, candidate.Path, candidate.Container}, "\n")
		if strings.Contains(haystack, value) {
			return true
		}
	}
	return false
}

// freezeHarnessBatchSize mirrors the application planner batch size so the
// walker blocks on queue backpressure mid-walk exactly as the scanner does.
const freezeHarnessBatchSize = 2048

// runFreezeTarget mirrors app.scanHost's producer/consumer wiring: shares are
// walked sequentially in one goroutine, the walk callback batches files and
// blocks on a jobs channel sized workers*2, and completion waits for the pool.
func runFreezeTarget(ctx context.Context, client *Client, engine scanner.Evaluator, sink *freezeSink, shares []string, workers int) error {
	if workers <= 0 {
		workers = 15
	}
	jobs := make(chan scanner.Job, workers*2)
	poolErrCh := make(chan error, 1)
	poolCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		poolErrCh <- scanner.NewWorkerPool(engine, sink, nil, nil, workers).Scan(poolCtx, jobs)
	}()

	var walkErrs []error
	for _, share := range shares {
		if err := ctx.Err(); err != nil {
			break
		}
		shareName := share
		sink.markShare(shareName)
		fileInputs := make([]RemoteFile, 0, freezeHarnessBatchSize)
		flush := func() error {
			if len(fileInputs) == 0 {
				return nil
			}
			for _, input := range fileInputs {
				remote := input
				remotePath := remote.Path
				job := scanner.Job{
					Metadata: scanner.FileMetadata{
						Host:       remote.Host,
						Share:      remote.Share,
						FilePath:   remote.Path,
						Name:       remote.Name,
						Extension:  remote.Extension,
						Size:       remote.Size,
						ModifiedAt: remote.ModifiedAt,
					},
					LoadContent: func(jobCtx context.Context, _ scanner.FileMetadata) ([]byte, error) {
						select {
						case <-jobCtx.Done():
							return nil, jobCtx.Err()
						default:
						}
						content, err := client.ReadFileContext(jobCtx, shareName, strings.ReplaceAll(remotePath, "/", `\`))
						if err == nil {
							sink.recordRead(shareName, remotePath)
						}
						return content, err
					},
				}
				select {
				case <-poolCtx.Done():
					return poolCtx.Err()
				case jobs <- job:
				}
			}
			fileInputs = fileInputs[:0]
			return nil
		}
		walkErr := client.WalkShareWithOptionsContext(ctx, shareName, WalkOptions{}, func(remote RemoteFile) error {
			if remote.IsDir {
				return nil
			}
			fileInputs = append(fileInputs, remote)
			if len(fileInputs) >= freezeHarnessBatchSize {
				return flush()
			}
			return nil
		})
		if walkErr != nil {
			walkErrs = append(walkErrs, fmt.Errorf("%s: %w", shareName, walkErr))
			continue
		}
		if err := flush(); err != nil {
			walkErrs = append(walkErrs, fmt.Errorf("%s: %w", shareName, err))
		}
	}
	close(jobs)
	poolErr := <-poolErrCh
	if poolErr != nil {
		return poolErr
	}
	return errors.Join(walkErrs...)
}

func freezeRules(t *testing.T) *rules.Manager {
	t.Helper()
	manager, issues, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(issues) > 0 {
		t.Fatalf("rule issues: %v", issues)
	}
	return manager
}

func newFreezeEngine(t *testing.T, sink scanner.FindingSink) *scanner.Engine {
	t.Helper()
	engine := scanner.NewEngine(scanner.Options{
		MaxFileSizeBytes: 8 << 20,
		MaxReadBytes:     8 << 20,
		SnippetBytes:     200,
	}, freezeRules(t), sink, logx.New("error"))
	if candidates, ok := sink.(scanner.CredentialCandidateSink); ok {
		engine.SetCredentialCandidateSink(candidates)
	}
	return engine
}

// newFreezeClient wires the real SMB client to the synthetic target and installs
// the failure observer used by the coverage assertions.
func newFreezeClient(t *testing.T, srv *freezeServer) (*Client, *freezeFailures) {
	t.Helper()
	client := NewClient()
	client.dialer = srv
	recallTimeouts(client)
	failures := &freezeFailures{}
	client.SetOperationFailureHandler(failures.record)
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("DOMAIN\\operator", "", "Secret-123!")); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		srv.releaseAll()
		_ = client.Close()
	})
	return client, failures
}

type freezeFailures struct {
	mu      sync.Mutex
	records []OperationFailure
}

func (f *freezeFailures) record(failure OperationFailure) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, failure)
}

func (f *freezeFailures) abandonmentFor(share string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, failure := range f.records {
		if failure.Share == share && strings.Contains(strings.ToLower(failure.Operation), "abandoned") {
			count++
		}
	}
	return count
}

func (f *freezeFailures) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

func (f *freezeFailures) snapshot() []OperationFailure {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]OperationFailure(nil), f.records...)
}

// runFreezeTargetBounded runs the target in a goroutine and fails if it does not
// return inside the bound, reporting exactly which shares were still stuck.
func runFreezeTargetBounded(t *testing.T, ctx context.Context, client *Client, engine scanner.Evaluator, sink *freezeSink, shares []string, workers int, bound time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- runFreezeTarget(ctx, client, engine, sink, shares, workers)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(bound):
		t.Fatalf("target did not complete within %s (shares started=%v): a single share still holds target progress", bound, sink.sharesStarted())
		return nil
	}
}

// requireGoroutinesSettle requires the goroutine count to fall back to the
// pre-test baseline, so a wedged call is never permanently leaked.
func requireGoroutinesSettle(t *testing.T, baseline int, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		runtime.Gosched()
		current := runtime.NumGoroutine()
		if current <= baseline+2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines did not settle: baseline=%d current=%d", baseline, current)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// seedControlFiles adds the permanent synthetic content controls used by the
// recall assertions. They are placed after the injected faults in walk order.
func seedControlFiles(srv *freezeServer, share string) {
	srv.addFile(share, "settings.ini", "[Default]\nAdminPassword=Synthetic-Admin-123!\n")
	srv.addFile(share, "OperationsGuide.docx", string(officefixture.DOCX(officefixture.Paragraph("Passordet er; Synthetic-Docx-123!"))))
	srv.addFile(share, "notes.txt", "Password=Synthetic-Txt-123!\n")
}

const (
	controlINI  = "Synthetic-Admin-123!"
	controlDOCX = "Synthetic-Docx-123!"
	controlTXT  = "Synthetic-Txt-123!"
)

func requireControlFindings(t *testing.T, sink *freezeSink) {
	t.Helper()
	if !sink.contentFinding("settings.ini", controlINI) {
		t.Fatalf("settings.ini credential was not reported after recovery (findings=%d)", sink.findingCount())
	}
	if !sink.contentFinding("OperationsGuide.docx", controlDOCX) {
		t.Fatal("OperationsGuide.docx credential was not reported after recovery")
	}
	if !sink.contentFinding("notes.txt", controlTXT) {
		t.Fatal("notes.txt credential was not reported after recovery")
	}
}

// requireControlReads proves the controls were content-read even when a parser
// chooses a different reporting path for one of them.
func requireControlReads(t *testing.T, sink *freezeSink, share string) {
	t.Helper()
	for _, name := range []string{"settings.ini", "OperationsGuide.docx", "notes.txt"} {
		if !sink.readOK(share, name) {
			t.Fatalf("control file %s on %s was not content-read", name, share)
		}
	}
}

// healthyPadding adds bulk to a share so the walk reaches the planner's batch
// size and blocks on queue backpressure mid-walk, exactly like the live handle.
func healthyPadding(srv *freezeServer, share string, count int) {
	for i := 1; i <= count; i++ {
		srv.addFile(share, fmt.Sprintf("bulk%04d.txt", i), "nothing interesting here")
	}
}

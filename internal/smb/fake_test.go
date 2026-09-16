package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// fakeServer is a scripted in-memory SMB server used for deterministic
// transport fault injection. Scripts are consumed per operation so a test can
// say "the first read of this file dies with ECONNRESET, the retry succeeds".
type fakeServer struct {
	mu sync.Mutex

	files map[string]map[string][]byte // share -> path -> content
	dirs  map[string][]string          // share -> entry names at the share root

	scripts map[string][]opScript // operation key -> queued results

	dials    int
	mounts   int
	reads    int
	dirsRead int
	dialAuth []resolvedAuth

	dialQueue []error // errors returned instead of a live session
}

type opScript struct {
	err       error
	partial   []byte // bytes delivered before err (mid-read reset)
	killTrunk bool   // the failure destroys the transport
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		files:   map[string]map[string][]byte{},
		dirs:    map[string][]string{},
		scripts: map[string][]opScript{},
	}
}

func (s *fakeServer) addFile(share, filePath string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files[share] == nil {
		s.files[share] = map[string][]byte{}
	}
	s.files[share][filePath] = content
}

func (s *fakeServer) setDirEntries(share string, names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirs[share] = append([]string(nil), names...)
}

// script queues results for one operation key. Keys are produced by the
// readKey/dirKey/mountKey helpers.
func (s *fakeServer) script(key string, results ...opScript) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[key] = append(s.scripts[key], results...)
}

func (s *fakeServer) queueDialError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dialQueue = append(s.dialQueue, err)
}

func (s *fakeServer) next(key string) (opScript, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	queue, ok := s.scripts[key]
	if !ok || len(queue) == 0 {
		return opScript{}, false
	}
	result := queue[0]
	s.scripts[key] = queue[1:]
	return result, true
}

func readKey(share, name string) string { return "read:" + share + "/" + name }
func dirKey(share, dir string) string   { return "dir:" + share + "/" + dir }
func mountKey(share string) string      { return "mount:" + share }

// resetError is what a real connection reset surfaces as: go-smb2 wraps the
// socket error in a typed TransportError.
func resetError() error { return &smb2.TransportError{Err: syscall.ECONNRESET} }

// deniedError is an ordinary SMB status that must never trigger a reconnect.
func deniedError() error { return &smb2.ResponseError{Code: ntStatusAccessDenied} }

const ntStatusLogonFailure = 0xC000006D

func logonFailureError() error { return &smb2.ResponseError{Code: ntStatusLogonFailure} }

func (s *fakeServer) Dial(_ context.Context, _ string, auth resolvedAuth, _ time.Duration) (transportSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials++
	s.dialAuth = append(s.dialAuth, auth)
	if len(s.dialQueue) > 0 {
		err := s.dialQueue[0]
		s.dialQueue = s.dialQueue[1:]
		return nil, err
	}
	return &fakeSession{server: s}, nil
}

func (s *fakeServer) dialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

type fakeSession struct {
	server *fakeServer
	dead   bool
	closed bool
}

func (s *fakeSession) Mount(mountPath string) (transportTree, error) {
	share := path.Base(strings.ReplaceAll(mountPath, `\`, "/"))
	s.server.mu.Lock()
	s.server.mounts++
	dead := s.dead || s.closed
	s.server.mu.Unlock()
	if dead {
		return nil, net.ErrClosed
	}
	if scripted, ok := s.server.next(mountKey(share)); ok {
		if scripted.killTrunk {
			s.kill()
		}
		if scripted.err != nil {
			return nil, scripted.err
		}
	}
	return &fakeTree{server: s.server, session: s, share: share}, nil
}

func (s *fakeSession) ListSharenames() ([]string, error) {
	s.server.mu.Lock()
	defer s.server.mu.Unlock()
	if s.dead || s.closed {
		return nil, net.ErrClosed
	}
	names := make([]string, 0, len(s.server.files))
	for share := range s.server.files {
		names = append(names, share)
	}
	sort.Strings(names)
	return names, nil
}

func (s *fakeSession) Close() error {
	s.server.mu.Lock()
	s.closed = true
	s.server.mu.Unlock()
	return nil
}

func (s *fakeSession) kill() {
	s.server.mu.Lock()
	s.dead = true
	s.server.mu.Unlock()
}

type fakeTree struct {
	server  *fakeServer
	session *fakeSession
	share   string
}

func (t *fakeTree) ReadDir(dir string) ([]fs.FileInfo, error) {
	t.server.mu.Lock()
	t.server.dirsRead++
	dead := t.session.dead || t.session.closed
	t.server.mu.Unlock()
	if dead {
		return nil, net.ErrClosed
	}
	if scripted, ok := t.server.next(dirKey(t.share, dir)); ok {
		if scripted.killTrunk {
			t.session.kill()
		}
		if scripted.err != nil {
			return nil, scripted.err
		}
	}
	t.server.mu.Lock()
	names := append([]string(nil), t.server.dirs[t.share]...)
	t.server.mu.Unlock()
	infos := make([]fs.FileInfo, 0, len(names))
	for _, name := range names {
		t.server.mu.Lock()
		content, isFile := t.server.files[t.share][name]
		t.server.mu.Unlock()
		if isFile {
			infos = append(infos, fakeFileInfo{name: name, size: int64(len(content))})
			continue
		}
		infos = append(infos, fakeFileInfo{name: name, dir: true})
	}
	return infos, nil
}

func (t *fakeTree) Stat(name string) (fs.FileInfo, error) {
	t.server.mu.Lock()
	dead := t.session.dead || t.session.closed
	content, ok := t.server.files[t.share][name]
	t.server.mu.Unlock()
	if dead {
		return nil, net.ErrClosed
	}
	if !ok {
		return nil, &smb2.ResponseError{Code: 0xC0000034} // OBJECT_NAME_NOT_FOUND
	}
	return fakeFileInfo{name: name, size: int64(len(content))}, nil
}

func (t *fakeTree) Open(name string) (transportFile, error) {
	t.server.mu.Lock()
	t.server.reads++
	dead := t.session.dead || t.session.closed
	content, ok := t.server.files[t.share][name]
	t.server.mu.Unlock()
	if dead {
		return nil, net.ErrClosed
	}
	if !ok {
		return nil, &smb2.ResponseError{Code: 0xC0000034}
	}
	file := &fakeFile{data: content}
	if scripted, has := t.server.next(readKey(t.share, name)); has {
		if scripted.killTrunk {
			t.session.kill()
		}
		if scripted.partial != nil {
			file.failAfter = len(scripted.partial)
			file.partial = scripted.partial
		}
		file.err = scripted.err
	}
	return file, nil
}

func (t *fakeTree) Umount() error { return nil }

func (t *fakeTree) MkdirAll(string, fs.FileMode) error { return nil }

func (t *fakeTree) WriteFile(string, []byte, fs.FileMode) error { return nil }

func (t *fakeTree) RemoveAll(string) error { return nil }

type fakeFile struct {
	data      []byte
	partial   []byte
	failAfter int // bytes of partial data to deliver before err
	err       error
	offset    int
	sent      int
}

func (f *fakeFile) Read(p []byte) (int, error) {
	if f.partial != nil && f.sent < f.failAfter {
		n := copy(p, f.partial[f.sent:f.failAfter])
		f.sent += n
		return n, nil
	}
	if f.err != nil {
		err := f.err
		f.err = nil
		if f.partial != nil {
			return 0, err
		}
		return 0, err
	}
	if f.offset >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.offset:])
	f.offset += n
	return n, nil
}

func (f *fakeFile) Close() error { return nil }

type fakeFileInfo struct {
	name string
	size int64
	dir  bool
}

func (fi fakeFileInfo) Name() string       { return fi.name }
func (fi fakeFileInfo) Size() int64        { return fi.size }
func (fi fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (fi fakeFileInfo) ModTime() time.Time { return time.Unix(1000, 0).UTC() }
func (fi fakeFileInfo) IsDir() bool        { return fi.dir }
func (fi fakeFileInfo) Sys() any           { return nil }

// newFaultyClient builds a client wired to a scripted server.
func newFaultyClient(t interface {
	Helper()
	Fatalf(string, ...any)
}, server *fakeServer) *Client {
	t.Helper()
	client := NewClient()
	client.dialer = server
	if err := client.ConnectWithAuth("fileserver.example.test", NewPasswordAuth("operator", "DOMAIN", "secret")); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	return client
}

var errFake = errors.New("fake")

func (s *fakeServer) String() string { return "fakeServer" }

func formatNames(names []string) string { return fmt.Sprintf("%v", names) }

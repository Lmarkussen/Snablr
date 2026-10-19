package state

import (
	"context"
	"strings"
	"sync"
	"time"
)

const defaultSaveInterval = 10 * time.Second

type shareProgress struct {
	failed    bool
	excluded  bool
	remaining int
	finished  bool
}

type Manager struct {
	store        *Store
	mu           sync.Mutex
	pending      map[string]*shareProgress
	shareStatus  map[string]string
	stateStore   SQLiteStateStore
	scanID       string
	resumeReader SQLiteResumeReader
}

func (m *Manager) AttachStore(stateStore SQLiteStateStore, scanID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.stateStore, m.scanID = stateStore, scanID
	m.mu.Unlock()
}

type SQLiteResumeReader interface {
	ResumeTargetComplete(string) (bool, error)
	ResumeShareComplete(string, string) (bool, error)
	LookupFile(string, string, string) (SQLiteFileState, bool, error)
	IsScopeExcluded(kind, host, share, path string) (bool, error)
}

type SQLiteFileState struct {
	Key, Host, Share, Path, Status, Semantics  string
	Size                                       int64
	ModifiedAt, FirstSeen, LastSeen, UpdatedAt time.Time
}

func NewManagerFromSQLiteReader(reader SQLiteResumeReader, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = defaultSaveInterval
	}
	return &Manager{store: newStore(), resumeReader: reader, pending: make(map[string]*shareProgress), shareStatus: make(map[string]string)}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.store != nil && (m.store.Enabled() || m.resumeReader != nil)
}

func (m *Manager) Start(context.Context) {}

func (m *Manager) Save() error { return nil }

func (m *Manager) Close() error { return nil }

func (m *Manager) ShouldSkipHost(host string) bool {
	if !m.Enabled() {
		return false
	}
	skip := false
	if m.resumeReader != nil {
		skip, _ = m.resumeReader.ResumeTargetComplete(host)
	} else {
		skip = m.store.IsHostComplete(host)
	}
	if skip && m.stateStore != nil {
		_ = m.stateStore.RecordTarget(host, "completed", time.Now().UTC())
	}
	return skip
}

func (m *Manager) ShouldSkipShare(host, share string) bool {
	if !m.Enabled() {
		return false
	}
	if m.IsScopeExcluded("share", host, share, "") {
		m.markShareStatus(host, share, "skipped")
		return true
	}
	skip := false
	if m.resumeReader != nil {
		skip, _ = m.resumeReader.ResumeShareComplete(host, share)
	} else {
		skip = m.store.IsShareComplete(host, share)
	}
	if skip && m.stateStore != nil {
		_ = m.stateStore.RecordShare(host, share, "completed", time.Now().UTC())
	}
	if skip {
		m.mu.Lock()
		m.shareStatus[ShareKey(host, share)] = "completed"
		m.mu.Unlock()
	}
	return skip
}

func (m *Manager) IsScopeExcluded(kind, host, share, path string) bool {
	if !m.Enabled() {
		return false
	}
	if m.resumeReader != nil {
		excluded, _ := m.resumeReader.IsScopeExcluded(kind, host, share, path)
		return excluded
	}
	if reader, ok := m.stateStore.(interface {
		IsScopeExcluded(string, string, string, string) (bool, error)
	}); ok {
		excluded, _ := reader.IsScopeExcluded(kind, host, share, path)
		return excluded
	}
	return false
}

func (m *Manager) ShouldDescend(host, share, path string) bool {
	return !m.IsScopeExcluded("share", host, share, "") && !m.IsScopeExcluded("folder", host, share, path)
}

func (m *Manager) SkipFolder(host, share, path string) error {
	if !m.Enabled() || m.stateStore == nil {
		return nil
	}
	if err := m.stateStore.RecordScopeExclusion("folder", host, share, path, time.Now().UTC()); err != nil {
		return err
	}
	key := ShareKey(host, share)
	m.mu.Lock()
	if progress := m.pending[key]; progress != nil {
		progress.excluded = true
	}
	m.shareStatus[key] = "skipped"
	m.mu.Unlock()
	return nil
}

func (m *Manager) SkipShare(host, share string) error {
	if !m.Enabled() || m.stateStore == nil {
		return nil
	}
	if err := m.stateStore.RecordScopeExclusion("share", host, share, "", time.Now().UTC()); err != nil {
		return err
	}
	m.markShareStatus(host, share, "skipped")
	return nil
}

func (m *Manager) markShareStatus(host, share, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shareStatus[ShareKey(host, share)] = status
	if progress := m.pending[ShareKey(host, share)]; progress != nil {
		progress.excluded = true
	}
	if m.stateStore != nil {
		_ = m.stateStore.RecordShare(host, share, status, time.Now().UTC())
	}
}

func (m *Manager) ShouldSkipFile(host, share, path string, size int64, modifiedAt time.Time) bool {
	if !m.Enabled() {
		return false
	}
	skip := false
	if m.resumeReader != nil {
		file, ok, _ := m.resumeReader.LookupFile(host, share, path)
		skip = ok && (file.Status == "completed" || file.Status == "skipped_unchanged") && file.Size == size && file.ModifiedAt.Equal(modifiedAt)
	} else {
		skip = m.store.IsFileComplete(host, share, path, size, modifiedAt)
	}
	if skip && m.stateStore != nil {
		_ = m.stateStore.RecordFile(FileKey(host, share, path), host, share, path, "completed", "", size, modifiedAt, time.Time{}, time.Time{}, time.Now().UTC())
	}
	return skip
}

func (m *Manager) BeginShare(host, share string, fileCount int) {
	if !m.Enabled() {
		return
	}

	if fileCount <= 0 {
		m.store.MarkShareComplete(host, share)
		m.mu.Lock()
		m.shareStatus[ShareKey(host, share)] = "completed"
		m.mu.Unlock()
		return
	}

	key := ShareKey(host, share)
	if key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending[key] = &shareProgress{remaining: fileCount, finished: true}
}

func (m *Manager) StartShare(host, share string) {
	if !m.Enabled() {
		return
	}
	key := ShareKey(host, share)
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[key]; ok {
		return
	}
	m.pending[key] = &shareProgress{}
	m.shareStatus[key] = "partial"
	if m.stateStore != nil {
		_ = m.stateStore.RecordShare(host, share, "partial", time.Now().UTC())
	}
}

func (m *Manager) AddPendingFiles(host, share string, fileCount int) {
	if !m.Enabled() || fileCount <= 0 {
		return
	}
	key := ShareKey(host, share)
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	progress, ok := m.pending[key]
	if !ok {
		progress = &shareProgress{}
		m.pending[key] = progress
	}
	progress.remaining += fileCount
}

func (m *Manager) FinishShareEnumeration(host, share string) {
	if !m.Enabled() {
		return
	}
	key := ShareKey(host, share)
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	progress, ok := m.pending[key]
	if !ok {
		m.store.MarkShareComplete(host, share)
		m.shareStatus[key] = "completed"
		return
	}
	progress.finished = true
	if progress.excluded {
		m.shareStatus[key] = "skipped"
		delete(m.pending, key)
		if m.stateStore != nil {
			_ = m.stateStore.RecordShare(host, share, "skipped", time.Now().UTC())
		}
		return
	}
	if progress.remaining > 0 {
		return
	}
	if !progress.failed {
		m.store.MarkShareComplete(host, share)
		m.shareStatus[key] = "completed"
		if m.stateStore != nil {
			_ = m.stateStore.RecordShare(host, share, "completed", time.Now().UTC())
		}
	} else {
		m.shareStatus[key] = "failed"
	}
	delete(m.pending, key)
}

func (m *Manager) AbortShare(host, share string) {
	if !m.Enabled() {
		return
	}
	key := ShareKey(host, share)
	if key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if progress, ok := m.pending[key]; ok {
		progress.failed = true
		delete(m.pending, key)
	}
	m.shareStatus[key] = "failed"
	if m.stateStore != nil {
		_ = m.stateStore.RecordShare(host, share, "failed", time.Now().UTC())
	}
}

func (m *Manager) RecordFileResult(host, share, path string, size int64, modifiedAt time.Time, success bool) {
	m.recordFileResult(host, share, path, size, modifiedAt, success, true)
}

// RecordFileResultInMemory updates host/share progress without writing the
// legacy file identity. The SQLite inventory owns file persistence when it is
// active; the manager still needs this transition to close share progress.
func (m *Manager) RecordFileResultInMemory(host, share, path string, size int64, modifiedAt time.Time, success bool) {
	m.recordFileResult(host, share, path, size, modifiedAt, success, false)
}

func (m *Manager) recordFileResult(host, share, path string, size int64, modifiedAt time.Time, success, persistFile bool) {
	if !m.Enabled() {
		return
	}

	if success {
		m.store.MarkFileComplete(host, share, path, size, modifiedAt)
	}
	if persistFile && m.stateStore != nil {
		status := "failed"
		if success {
			status = "completed"
		}
		_ = m.stateStore.RecordFile(FileKey(host, share, path), host, share, path, status, "", size, modifiedAt, time.Time{}, time.Time{}, time.Now().UTC())
	}

	key := ShareKey(host, share)
	if key == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	progress, ok := m.pending[key]
	if !ok {
		return
	}
	if progress.excluded {
		if progress.remaining > 0 {
			progress.remaining--
		}
		if progress.finished && progress.remaining <= 0 {
			m.shareStatus[key] = "skipped"
			delete(m.pending, key)
		}
		return
	}
	if !success {
		progress.failed = true
	}
	progress.remaining--
	if progress.remaining > 0 || !progress.finished {
		return
	}

	if !progress.failed {
		m.store.MarkShareComplete(host, share)
		m.shareStatus[key] = "completed"
		if m.stateStore != nil {
			_ = m.stateStore.RecordShare(host, share, "completed", time.Now().UTC())
		}
	} else {
		m.shareStatus[key] = "failed"
	}
	delete(m.pending, key)
}

// HostComplete reports whether every share in the current filtered plan
// completed successfully. Reused completed shares are recorded by
// ShouldSkipShare so they count toward the current plan.
func (m *Manager) HostComplete(host string, expectedShares int) bool {
	if !m.Enabled() {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := HostKey(host) + "::"
	seen, completed := 0, 0
	for key, status := range m.shareStatus {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		seen++
		if status == "completed" {
			completed++
		}
	}
	return seen >= expectedShares && completed >= expectedShares
}

func (m *Manager) MarkHostComplete(host string) {
	if !m.Enabled() {
		return
	}
	m.store.MarkHostComplete(host)
	if m.stateStore != nil {
		_ = m.stateStore.RecordTarget(host, "completed", time.Now().UTC())
	}
}

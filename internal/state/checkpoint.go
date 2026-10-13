package state

import (
	"context"
	"sync"
	"time"
)

const defaultSaveInterval = 10 * time.Second

type shareProgress struct {
	failed    bool
	remaining int
	finished  bool
}

type Manager struct {
	store    *Store
	interval time.Duration

	mu      sync.Mutex
	pending map[string]*shareProgress
	started bool

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
	shadow   ShadowStore
	scanID   string
}

func (m *Manager) AttachShadow(shadow ShadowStore, scanID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.shadow, m.scanID = shadow, scanID
	m.mu.Unlock()
}

func NewManager(path string, resume bool, interval time.Duration) (*Manager, error) {
	store, err := Open(path, resume)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, nil
	}
	if interval <= 0 {
		interval = defaultSaveInterval
	}
	return &Manager{
		store:    store,
		interval: interval,
		pending:  make(map[string]*shareProgress),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// NewManagerFromSQLite adapts a validated SQLite logical state to the same
// checkpoint decisions used by JSON. It is intentionally only used by the
// experimental SQLite resume path.
type SQLiteResumeState struct {
	SemanticsMatch bool
	Targets        []SQLiteTargetState
	Shares         []SQLiteShareState
	Files          []SQLiteFileState
	Access         []SQLiteAccessState
}

type SQLiteTargetState struct{ Host, Status string }
type SQLiteShareState struct{ Host, Share, Status string }
type SQLiteFileState struct {
	Key, Host, Share, Path, Status, Semantics  string
	Size                                       int64
	ModifiedAt, FirstSeen, LastSeen, UpdatedAt time.Time
}
type SQLiteAccessState struct {
	ContextID, FileKey, Result string
	FirstSeen, LastSeen        time.Time
}

func NewManagerFromSQLite(resume SQLiteResumeState, interval time.Duration) *Manager {
	checkpoint := &Store{files: make(map[string]fileState), hosts: make(map[string]struct{}), shares: make(map[string]struct{})}
	if resume.SemanticsMatch {
		for _, target := range resume.Targets {
			if target.Status == "completed" {
				checkpoint.hosts[HostKey(target.Host)] = struct{}{}
			}
		}
		for _, share := range resume.Shares {
			if share.Status == "completed" {
				checkpoint.shares[ShareKey(share.Host, share.Share)] = struct{}{}
			}
		}
		for _, file := range resume.Files {
			if file.Status == "completed" || file.Status == "skipped_unchanged" {
				checkpoint.files[normalizeKey(file.Key)] = fileState{Size: file.Size, ModifiedAt: file.ModifiedAt}
			}
		}
	}
	if interval <= 0 {
		interval = defaultSaveInterval
	}
	return &Manager{store: checkpoint, interval: interval, pending: make(map[string]*shareProgress), stopCh: make(chan struct{}), doneCh: make(chan struct{})}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.store != nil && m.store.Enabled()
}

func (m *Manager) Start(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	ticker := time.NewTicker(m.interval)
	go func() {
		defer func() {
			ticker.Stop()
			close(m.doneCh)
		}()
		for {
			select {
			case <-ctx.Done():
				_ = m.Save()
				return
			case <-m.stopCh:
				_ = m.Save()
				return
			case <-ticker.C:
				_ = m.Save()
			}
		}
	}()
}

func (m *Manager) Save() error {
	if !m.Enabled() {
		return nil
	}
	return m.store.Save()
}

func (m *Manager) Close() error {
	if m != nil {
		m.stopOnce.Do(func() {
			close(m.stopCh)
			m.mu.Lock()
			started := m.started
			m.mu.Unlock()
			if started {
				<-m.doneCh
			}
		})
	}
	return m.Save()
}

func (m *Manager) ShouldSkipHost(host string) bool {
	if !m.Enabled() {
		return false
	}
	skip := m.store.IsHostComplete(host)
	if skip && m.shadow != nil {
		_ = m.shadow.RecordTarget(host, "completed", time.Now().UTC())
	}
	return skip
}

func (m *Manager) ShouldSkipShare(host, share string) bool {
	if !m.Enabled() {
		return false
	}
	skip := m.store.IsShareComplete(host, share)
	if skip && m.shadow != nil {
		_ = m.shadow.RecordShare(host, share, "completed", time.Now().UTC())
	}
	return skip
}

func (m *Manager) ShouldSkipFile(host, share, path string, size int64, modifiedAt time.Time) bool {
	if !m.Enabled() {
		return false
	}
	skip := m.store.IsFileComplete(host, share, path, size, modifiedAt)
	if skip && m.shadow != nil {
		_ = m.shadow.RecordFile(FileKey(host, share, path), host, share, path, "completed", "", size, modifiedAt, time.Time{}, time.Time{}, time.Now().UTC())
	}
	return skip
}

func (m *Manager) BeginShare(host, share string, fileCount int) {
	if !m.Enabled() {
		return
	}

	if fileCount <= 0 {
		m.store.MarkShareComplete(host, share)
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
	if m.shadow != nil {
		_ = m.shadow.RecordShare(host, share, "partial", time.Now().UTC())
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
		return
	}
	progress.finished = true
	if progress.remaining > 0 {
		return
	}
	if !progress.failed {
		m.store.MarkShareComplete(host, share)
		if m.shadow != nil {
			_ = m.shadow.RecordShare(host, share, "completed", time.Now().UTC())
		}
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
	if m.shadow != nil {
		_ = m.shadow.RecordShare(host, share, "failed", time.Now().UTC())
	}
}

func (m *Manager) RecordFileResult(host, share, path string, size int64, modifiedAt time.Time, success bool) {
	if !m.Enabled() {
		return
	}

	if success {
		m.store.MarkFileComplete(host, share, path, size, modifiedAt)
	}
	if m.shadow != nil {
		status := "failed"
		if success {
			status = "completed"
		}
		_ = m.shadow.RecordFile(FileKey(host, share, path), host, share, path, status, "", size, modifiedAt, time.Time{}, time.Time{}, time.Now().UTC())
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
	if !success {
		progress.failed = true
	}
	progress.remaining--
	if progress.remaining > 0 || !progress.finished {
		return
	}

	if !progress.failed {
		m.store.MarkShareComplete(host, share)
	}
	delete(m.pending, key)
}

func (m *Manager) MarkHostComplete(host string) {
	if !m.Enabled() {
		return
	}
	m.store.MarkHostComplete(host)
	if m.shadow != nil {
		_ = m.shadow.RecordTarget(host, "completed", time.Now().UTC())
	}
}

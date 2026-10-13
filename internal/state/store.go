package state

import (
	"strings"
	"sync"
	"time"
)

type fileState struct {
	Size       int64
	ModifiedAt time.Time
}

type Store struct {
	mu     sync.RWMutex
	files  map[string]fileState
	hosts  map[string]struct{}
	shares map[string]struct{}
}

func newStore() *Store {
	return &Store{files: make(map[string]fileState), hosts: make(map[string]struct{}), shares: make(map[string]struct{})}
}

func (s *Store) Enabled() bool { return s != nil }

func (s *Store) IsHostComplete(host string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.hosts[HostKey(host)]
	return ok
}
func (s *Store) IsShareComplete(host, share string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.shares[ShareKey(host, share)]
	return ok
}
func (s *Store) IsFileComplete(host, share, path string, size int64, modifiedAt time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.files[FileKey(host, share, path)]
	return ok && state.Size == size && (state.ModifiedAt.IsZero() || modifiedAt.IsZero() || state.ModifiedAt.Equal(modifiedAt.UTC()))
}
func (s *Store) MarkHostComplete(host string) {
	if s != nil {
		s.mu.Lock()
		s.hosts[HostKey(host)] = struct{}{}
		s.mu.Unlock()
	}
}
func (s *Store) MarkShareComplete(host, share string) {
	if s != nil {
		s.mu.Lock()
		s.shares[ShareKey(host, share)] = struct{}{}
		s.mu.Unlock()
	}
}
func (s *Store) MarkFileComplete(host, share, path string, size int64, modifiedAt time.Time) {
	if s != nil {
		s.mu.Lock()
		s.files[FileKey(host, share, path)] = fileState{Size: size, ModifiedAt: modifiedAt.UTC()}
		s.mu.Unlock()
	}
}

func HostKey(host string) string { return normalizeKey(host) }
func ShareKey(host, share string) string {
	host, share = normalizeKey(host), normalizeKey(share)
	if host == "" || share == "" {
		return ""
	}
	return host + "::" + share
}
func FileKey(host, share, path string) string {
	key := ShareKey(host, share)
	path = normalizeKey(strings.ReplaceAll(path, `\`, `/`))
	if key == "" || path == "" {
		return ""
	}
	return key + "::" + path
}
func normalizeKey(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

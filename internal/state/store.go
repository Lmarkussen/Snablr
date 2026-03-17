package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const checkpointVersion = 2

type fileState struct {
	Size       int64
	ModifiedAt time.Time
	Legacy     bool
}

type Store struct {
	path   string
	dirty  bool
	mu     sync.RWMutex
	files  map[string]fileState
	hosts  map[string]struct{}
	shares map[string]struct{}
}

func Open(path string, resume bool) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	store := &Store{
		path:   path,
		files:  make(map[string]fileState),
		hosts:  make(map[string]struct{}),
		shares: make(map[string]struct{}),
	}

	if !resume {
		return store, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("checkpoint file %s does not exist", path)
		}
		return nil, fmt.Errorf("read checkpoint file %s: %w", path, err)
	}

	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("parse checkpoint file %s: %w", path, err)
	}
	if checkpoint.Version != 0 && checkpoint.Version != 1 && checkpoint.Version != checkpointVersion {
		return nil, fmt.Errorf("checkpoint file %s uses unsupported version %d", path, checkpoint.Version)
	}

	for _, host := range checkpoint.CompletedHosts {
		store.hosts[normalizeKey(host)] = struct{}{}
	}
	for _, share := range checkpoint.CompletedShares {
		store.shares[normalizeKey(share)] = struct{}{}
	}
	for _, file := range checkpoint.CompletedFiles {
		store.files[normalizeKey(file)] = fileState{Legacy: true}
	}
	for _, file := range checkpoint.FileStates {
		key := normalizeKey(file.Key)
		if key == "" {
			continue
		}
		store.files[key] = fileState{
			Size:       file.Size,
			ModifiedAt: file.ModifiedAt.UTC(),
		}
	}

	return store, nil
}

func (s *Store) Enabled() bool {
	return s != nil && strings.TrimSpace(s.path) != ""
}

func (s *Store) Save() error {
	if s == nil || !s.Enabled() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty && fileExists(s.path) {
		return nil
	}

	checkpoint := Checkpoint{
		Version:         checkpointVersion,
		UpdatedAt:       time.Now().UTC(),
		CompletedHosts:  sortedKeys(s.hosts),
		CompletedShares: sortedKeys(s.shares),
		CompletedFiles:  legacyFileKeys(s.files),
		FileStates:      sortedFileStates(s.files),
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create checkpoint directory: %w", err)
	}

	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	data = append(data, '\n')

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write checkpoint temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace checkpoint file: %w", err)
	}

	s.dirty = false
	return nil
}

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
	if !ok {
		return false
	}
	if state.Legacy {
		return true
	}
	if state.Size != size {
		return false
	}
	if !state.ModifiedAt.IsZero() && !modifiedAt.IsZero() && !state.ModifiedAt.Equal(modifiedAt.UTC()) {
		return false
	}
	return ok
}

func (s *Store) MarkHostComplete(host string) {
	if s == nil {
		return
	}
	s.mark(s.hosts, HostKey(host))
}

func (s *Store) MarkShareComplete(host, share string) {
	if s == nil {
		return
	}
	s.mark(s.shares, ShareKey(host, share))
}

func (s *Store) MarkFileComplete(host, share, path string, size int64, modifiedAt time.Time) {
	if s == nil {
		return
	}
	s.markFile(FileKey(host, share, path), fileState{
		Size:       size,
		ModifiedAt: modifiedAt.UTC(),
	})
}

func (s *Store) mark(bucket map[string]struct{}, key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := bucket[key]; ok {
		return
	}
	bucket[key] = struct{}{}
	s.dirty = true
}

func (s *Store) markFile(key string, state fileState) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.files[key]
	if ok && current == state {
		return
	}
	s.files[key] = state
	s.dirty = true
}

func HostKey(host string) string {
	return normalizeKey(host)
}

func ShareKey(host, share string) string {
	host = normalizeKey(host)
	share = normalizeKey(share)
	if host == "" || share == "" {
		return ""
	}
	return host + "::" + share
}

func FileKey(host, share, path string) string {
	shareKey := ShareKey(host, share)
	path = normalizeKey(strings.ReplaceAll(path, `\`, `/`))
	if shareKey == "" || path == "" {
		return ""
	}
	return shareKey + "::" + path
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func legacyFileKeys(values map[string]fileState) []string {
	out := make([]string, 0)
	for key, state := range values {
		if state.Legacy {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func sortedFileStates(values map[string]fileState) []CompletedFileState {
	out := make([]CompletedFileState, 0, len(values))
	for key, state := range values {
		if state.Legacy {
			continue
		}
		out = append(out, CompletedFileState{
			Key:        key,
			Size:       state.Size,
			ModifiedAt: state.ModifiedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key < out[j].Key
	})
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

const SchemaVersion = 1

type Options struct {
	ScanID        string
	SnablrVersion string
	Semantics     string
	QueueSize     int
	BatchSize     int
	FlushEvery    time.Duration
}

type Status string

const (
	StatusRunning     Status = "running"
	StatusCompleted   Status = "completed"
	StatusInterrupted Status = "interrupted"
	StatusTimedOut    Status = "timed_out"
	StatusFailed      Status = "failed"
)

type FileState struct {
	Key, Host, Share, Path, Status, Semantics  string
	Size                                       int64
	ModifiedAt, FirstSeen, LastSeen, UpdatedAt time.Time
}

type ShadowStore struct {
	db        *sql.DB
	path      string
	scanID    string
	queue     chan event
	batch     int
	interval  time.Duration
	done      chan struct{}
	closeOnce sync.Once
	mu        sync.RWMutex
	closed    bool
	healthy   bool
	firstErr  error
}

func (s *ShadowStore) ScanID() string {
	if s == nil {
		return ""
	}
	return s.scanID
}

type event struct {
	apply   func(*sql.Tx) error
	barrier chan error
}

func Open(path string, options Options) (*ShadowStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite shadow store path cannot be empty")
	}
	if options.ScanID == "" {
		options.ScanID = fmt.Sprintf("scan-%d", time.Now().UTC().UnixNano())
	}
	if options.QueueSize <= 0 {
		options.QueueSize = 2048
	}
	if options.BatchSize <= 0 {
		options.BatchSize = 256
	}
	if options.FlushEvery <= 0 {
		options.FlushEvery = 100 * time.Millisecond
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite shadow store: %w", err)
	}
	cleanup := func(e error) (*ShadowStore, error) { _ = db.Close(); return nil, e }
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			return cleanup(fmt.Errorf("configure sqlite shadow store: %w", err))
		}
	}
	if err := initializeSchema(db); err != nil {
		return cleanup(err)
	}
	_ = os.Chmod(path, 0o600)
	s := &ShadowStore{db: db, path: path, scanID: options.ScanID, queue: make(chan event, options.QueueSize), batch: options.BatchSize, interval: options.FlushEvery, done: make(chan struct{}), healthy: true}
	if err := s.BeginScan(options.ScanID, options.SnablrVersion, options.Semantics, time.Now().UTC()); err != nil {
		return cleanup(err)
	}
	go s.run()
	return s, nil
}

func initializeSchema(db *sql.DB) error {
	var storedVersion string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&storedVersion); err == nil {
		if storedVersion != "1" {
			return fmt.Errorf("unsupported sqlite shadow schema version %s", storedVersion)
		}
	} else if !errors.Is(err, sql.ErrNoRows) && !strings.Contains(err.Error(), "no such table") {
		return err
	}
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, snablr_version TEXT, semantics TEXT, started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets (scan_id TEXT NOT NULL, host TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (scan_id, host), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS shares (scan_id TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (scan_id, host, share), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS files (scan_id TEXT NOT NULL, file_key TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, modified_at TEXT, first_seen TEXT, last_seen TEXT, updated_at TEXT NOT NULL, status TEXT NOT NULL, semantics TEXT NOT NULL, PRIMARY KEY (scan_id, file_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS access_observations (scan_id TEXT NOT NULL, context_id TEXT NOT NULL, file_key TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, access_result TEXT NOT NULL, PRIMARY KEY (scan_id, context_id, file_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS members (scan_id TEXT NOT NULL, parent_key TEXT NOT NULL, member_key TEXT NOT NULL, member_type TEXT NOT NULL, member_path TEXT NOT NULL, status TEXT NOT NULL, provenance TEXT, PRIMARY KEY (scan_id, parent_key, member_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, fingerprint TEXT NOT NULL, host TEXT, share TEXT, path TEXT, rule_id TEXT, category TEXT, payload TEXT NOT NULL, UNIQUE(scan_id, fingerprint), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, credential_key TEXT NOT NULL, credential_type TEXT, identity TEXT, value TEXT, payload TEXT NOT NULL, UNIQUE(scan_id, credential_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE TABLE IF NOT EXISTS correlations (scan_id TEXT NOT NULL, correlation_key TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (scan_id, correlation_key), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE INDEX IF NOT EXISTS files_status_idx ON files(scan_id, status);
CREATE INDEX IF NOT EXISTS findings_path_idx ON findings(scan_id, path);
INSERT INTO metadata(key, value) VALUES ('schema_version', '1') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
`)
	return err
}

func (s *ShadowStore) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	batch := make([]event, 0, s.batch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.commit(batch); err != nil {
			s.markUnhealthy(err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			if e.barrier != nil {
				flush()
				e.barrier <- s.healthError()
				continue
			}
			if s.healthError() != nil {
				continue
			}
			batch = append(batch, e)
			if len(batch) >= s.batch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *ShadowStore) commit(events []event) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := e.apply(tx); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.restrictSidecars()
}

func (s *ShadowStore) enqueue(apply func(*sql.Tx) error) error {
	if err := s.healthError(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("sqlite shadow store is closed")
	}
	s.queue <- event{apply: apply}
	return nil
}

func (s *ShadowStore) Flush() error {
	if s == nil {
		return nil
	}
	if err := s.healthError(); err != nil {
		return err
	}
	barrier := make(chan error, 1)
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errors.New("sqlite shadow store is closed")
	}
	s.queue <- event{barrier: barrier}
	s.mu.RUnlock()
	return <-barrier
}

func (s *ShadowStore) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		<-s.done
		_ = s.restrictSidecars()
		_ = s.db.Close()
	})
	return s.healthError()
}

func (s *ShadowStore) Healthy() bool      { return s != nil && s.healthError() == nil }
func (s *ShadowStore) healthError() error { s.mu.RLock(); defer s.mu.RUnlock(); return s.firstErr }
func (s *ShadowStore) markUnhealthy(err error) {
	s.mu.Lock()
	if s.firstErr == nil {
		s.firstErr = fmt.Errorf("sqlite shadow store disabled after write failure: %w", err)
	}
	s.mu.Unlock()
}
func (s *ShadowStore) restrictSidecars() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(s.path + suffix); err == nil {
			_ = os.Chmod(s.path+suffix, 0o600)
		}
	}
	return nil
}

func (s *ShadowStore) BeginScan(id, version, semantics string, started time.Time) error {
	s.scanID = id
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO scans(scan_id,schema_version,snablr_version,semantics,started_at,status) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET snablr_version=excluded.snablr_version, semantics=excluded.semantics`, id, SchemaVersion, version, semantics, started.UTC().Format(time.RFC3339Nano), StatusRunning)
		return err
	})
}
func (s *ShadowStore) SetScanStatus(status Status, ended time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE scans SET status=?, ended_at=? WHERE scan_id=?`, status, ended.UTC().Format(time.RFC3339Nano), s.scanID)
		return err
	})
}
func (s *ShadowStore) RecordTarget(host, status string, at time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO targets(scan_id,host,status,updated_at) VALUES(?,?,?,?) ON CONFLICT(scan_id,host) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at`, s.scanID, host, status, at.UTC().Format(time.RFC3339Nano))
		return err
	})
}
func (s *ShadowStore) RecordShare(host, share, status string, at time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO shares(scan_id,host,share,status,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(scan_id,host,share) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at`, s.scanID, host, share, status, at.UTC().Format(time.RFC3339Nano))
		return err
	})
}
func (s *ShadowStore) RecordFile(key, host, share, path, status, semantics string, size int64, modifiedAt, firstSeen, lastSeen, updatedAt time.Time) error {
	f := FileState{Key: key, Host: host, Share: share, Path: path, Status: status, Semantics: semantics, Size: size, ModifiedAt: modifiedAt, FirstSeen: firstSeen, LastSeen: lastSeen, UpdatedAt: updatedAt}
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO files(scan_id,file_key,host,share,path,size,modified_at,first_seen,last_seen,updated_at,status,semantics) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scan_id,file_key) DO UPDATE SET size=excluded.size,modified_at=excluded.modified_at,last_seen=excluded.last_seen,updated_at=excluded.updated_at,status=excluded.status,semantics=excluded.semantics`, s.scanID, f.Key, f.Host, f.Share, f.Path, f.Size, timeString(f.ModifiedAt), timeString(f.FirstSeen), timeString(f.LastSeen), timeString(f.UpdatedAt), f.Status, f.Semantics)
		return err
	})
}
func (s *ShadowStore) RecordAccess(contextID, fileKey, result string, first, last time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO access_observations(scan_id,context_id,file_key,first_seen,last_seen,access_result) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,context_id,file_key) DO UPDATE SET last_seen=excluded.last_seen,access_result=excluded.access_result`, s.scanID, contextID, fileKey, timeString(first), timeString(last), result)
		return err
	})
}
func (s *ShadowStore) RecordMember(parent, member, kind, memberPath, status, provenance string) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO members(scan_id,parent_key,member_key,member_type,member_path,status,provenance) VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,parent_key,member_key) DO UPDATE SET status=excluded.status,provenance=excluded.provenance`, s.scanID, parent, member, kind, memberPath, status, provenance)
		return err
	})
}
func (s *ShadowStore) RecordFinding(f scanner.Finding) error {
	payload, _ := json.Marshal(f)
	digest := sha256.Sum256(payload)
	fingerprint := fmt.Sprintf("%x", digest[:])
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO findings(scan_id,fingerprint,host,share,path,rule_id,category,payload) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scan_id,fingerprint) DO UPDATE SET payload=excluded.payload`, s.scanID, fingerprint, f.Host, f.Share, f.FilePath, f.RuleID, f.Category, payload)
		return err
	})
}
func (s *ShadowStore) RecordCredential(c credentialanalysis.Candidate) error {
	payload, _ := credentialPayload(c)
	key := fmt.Sprintf("%s|%s|%s|%s", c.CredentialType, c.Identity, c.Path, c.Value)
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO credentials(scan_id,credential_key,credential_type,identity,value,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,credential_key) DO UPDATE SET payload=excluded.payload,value=excluded.value`, s.scanID, key, c.CredentialType, c.Identity, c.Value, payload)
		return err
	})
}

func credentialPayload(c credentialanalysis.Candidate) ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	object["value"] = c.Value
	return json.Marshal(object)
}
func (s *ShadowStore) RecordCorrelation(key string, payload any) error {
	data, _ := json.Marshal(payload)
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO correlations(scan_id,correlation_key,payload) VALUES(?,?,?) ON CONFLICT(scan_id,correlation_key) DO UPDATE SET payload=excluded.payload`, s.scanID, key, data)
		return err
	})
}
func timeString(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ShadowSink forwards output events while making persistence failures non-fatal.
type ShadowSink struct {
	underlying scanner.FindingSink
	store      *ShadowStore
}

func WrapSink(underlying scanner.FindingSink, shadow *ShadowStore) *ShadowSink {
	return &ShadowSink{underlying: underlying, store: shadow}
}
func (s *ShadowSink) WriteFinding(f scanner.Finding) error {
	if err := s.store.RecordFinding(f); err != nil {
	}
	return s.underlying.WriteFinding(f)
}
func (s *ShadowSink) Close() error { return s.underlying.Close() }
func (s *ShadowSink) RecordCredentialCandidate(c credentialanalysis.Candidate) error {
	_ = s.store.RecordCredential(c)
	if r, ok := s.underlying.(scanner.CredentialCandidateSink); ok {
		return r.RecordCredentialCandidate(c)
	}
	return nil
}
func (s *ShadowSink) ExportNTDSCurrentHash(domain, account, source string, rid uint32, sid string, machine, disabled bool, hash []byte) error {
	if e, ok := s.underlying.(scanner.SensitiveCredentialExporter); ok {
		return e.ExportNTDSCurrentHash(domain, account, source, rid, sid, machine, disabled, hash)
	}
	return nil
}

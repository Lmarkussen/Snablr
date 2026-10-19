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

const SchemaVersion = 2

const (
	ScopeExclusionShare  = "share"
	ScopeExclusionFolder = "folder"
)

type Options struct {
	ScanID        string
	SnablrVersion string
	Semantics     string
	QueueSize     int
	BatchSize     int
	FlushEvery    time.Duration
	// FailAfterBatches is test-only fault injection. Zero disables it.
	FailAfterBatches int
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

type SQLiteStore struct {
	db               *sql.DB
	path             string
	scanID           string
	queue            chan event
	batch            int
	interval         time.Duration
	done             chan struct{}
	closeOnce        sync.Once
	mu               sync.RWMutex
	closed           bool
	healthy          bool
	firstErr         error
	committedBatches int
	failAfterBatches int
}

func (s *SQLiteStore) ScanID() string {
	if s == nil {
		return ""
	}
	return s.scanID
}

type event struct {
	apply   func(*sql.Tx) error
	barrier chan error
}

func Open(path string, options Options) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite state store path cannot be empty")
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
		return nil, fmt.Errorf("open sqlite state store: %w", err)
	}
	cleanup := func(e error) (*SQLiteStore, error) { _ = db.Close(); return nil, e }
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			return cleanup(fmt.Errorf("configure sqlite state store: %w", err))
		}
	}
	if err := initializeSchema(db); err != nil {
		return cleanup(err)
	}
	_ = os.Chmod(path, 0o600)
	s := &SQLiteStore{db: db, path: path, scanID: options.ScanID, queue: make(chan event, options.QueueSize), batch: options.BatchSize, interval: options.FlushEvery, done: make(chan struct{}), healthy: true, failAfterBatches: options.FailAfterBatches}
	if err := s.BeginScan(options.ScanID, options.SnablrVersion, options.Semantics, time.Now().UTC()); err != nil {
		return cleanup(err)
	}
	go s.run()
	return s, nil
}

func initializeSchema(db *sql.DB) error {
	var storedVersion string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&storedVersion); err == nil {
		if storedVersion == "1" {
			if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS bookmarks (scan_id TEXT NOT NULL, file_key TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, file_key), FOREIGN KEY (scan_id, file_key) REFERENCES files(scan_id, file_key));
CREATE TABLE IF NOT EXISTS scope_exclusions (scan_id TEXT NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, kind, host, share, path), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE INDEX IF NOT EXISTS bookmarks_scan_created_idx ON bookmarks(scan_id, created_at, file_key);
CREATE INDEX IF NOT EXISTS scope_exclusions_identity_idx ON scope_exclusions(scan_id, kind, host, share, path);
UPDATE metadata SET value='2' WHERE key='schema_version';
`); err != nil {
				return fmt.Errorf("migrate SQLite scan database schema: %w", err)
			}
			return nil
		}
		if storedVersion != "2" {
			return fmt.Errorf("unsupported SQLite scan database schema version %s", storedVersion)
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
CREATE TABLE IF NOT EXISTS bookmarks (scan_id TEXT NOT NULL, file_key TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, file_key), FOREIGN KEY (scan_id, file_key) REFERENCES files(scan_id, file_key));
CREATE TABLE IF NOT EXISTS scope_exclusions (scan_id TEXT NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (scan_id, kind, host, share, path), FOREIGN KEY (scan_id) REFERENCES scans(scan_id));
CREATE INDEX IF NOT EXISTS files_status_idx ON files(scan_id, status);
CREATE INDEX IF NOT EXISTS files_identity_idx ON files(scan_id, host, share, path);
CREATE INDEX IF NOT EXISTS findings_path_idx ON findings(scan_id, path);
CREATE INDEX IF NOT EXISTS bookmarks_scan_created_idx ON bookmarks(scan_id, created_at, file_key);
CREATE INDEX IF NOT EXISTS scope_exclusions_identity_idx ON scope_exclusions(scan_id, kind, host, share, path);
INSERT INTO metadata(key, value) VALUES ('schema_version', '2') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
`)
	return err
}

// RecordScopeExclusion waits for the authoritative transaction to commit.
func (s *SQLiteStore) RecordScopeExclusion(kind, host, share, path string, at time.Time) error {
	if s == nil {
		return errors.New("sqlite state store is nil")
	}
	host, share, path = normalizeScopeIdentity(host, share, path)
	if kind != ScopeExclusionShare && kind != ScopeExclusionFolder {
		return fmt.Errorf("unsupported scope exclusion kind %q", kind)
	}
	if kind == ScopeExclusionShare {
		path = ""
	} else if path == "" {
		return errors.New("folder exclusion path cannot be empty")
	}
	if host == "" || share == "" {
		return errors.New("scope exclusion requires host and share")
	}
	if err := s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR IGNORE INTO scope_exclusions(scan_id,kind,host,share,path,created_at) VALUES(?,?,?,?,?,?)`, s.scanID, kind, host, share, path, at.UTC().Format(time.RFC3339Nano))
		return err
	}); err != nil {
		return err
	}
	return s.Flush()
}

func (s *SQLiteStore) IsScopeExcluded(kind, host, share, path string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("sqlite state store is closed")
	}
	host, share, path = normalizeScopeIdentity(host, share, path)
	if kind == ScopeExclusionShare {
		path = ""
	}
	var marker int
	if kind == ScopeExclusionFolder {
		rows, err := s.db.Query(`SELECT path FROM scope_exclusions WHERE scan_id=? AND kind=? AND host=? AND share=?`, s.scanID, kind, host, share)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var excluded string
			if err := rows.Scan(&excluded); err != nil {
				return false, err
			}
			if path == excluded || strings.HasPrefix(path, excluded+"/") {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	err := s.db.QueryRow(`SELECT 1 FROM scope_exclusions WHERE scan_id=? AND kind=? AND host=? AND share=? AND path=?`, s.scanID, kind, host, share, path).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return marker == 1, err
}

func normalizeScopeIdentity(host, share, path string) (string, string, string) {
	host = strings.ToLower(strings.TrimSpace(host))
	share = strings.ToLower(strings.Trim(strings.TrimSpace(share), `/\\`))
	path = strings.ReplaceAll(strings.TrimSpace(path), `\\`, "/")
	path = strings.Trim(path, "/")
	parts := make([]string, 0)
	for _, part := range strings.Split(path, "/") {
		if part != "" && part != "." {
			parts = append(parts, strings.ToLower(part))
		}
	}
	return host, share, strings.Join(parts, "/")
}

func (s *SQLiteStore) run() {
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

func (s *SQLiteStore) commit(events []event) error {
	if s.failAfterBatches > 0 && s.committedBatches >= s.failAfterBatches {
		return errors.New("synthetic authoritative SQLite write failure")
	}
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
	s.committedBatches++
	return s.restrictSidecars()
}

func (s *SQLiteStore) enqueue(apply func(*sql.Tx) error) error {
	if err := s.healthError(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("sqlite state store is closed")
	}
	s.queue <- event{apply: apply}
	return nil
}

func (s *SQLiteStore) Flush() error {
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
		return errors.New("sqlite state store is closed")
	}
	s.queue <- event{barrier: barrier}
	s.mu.RUnlock()
	return <-barrier
}

func (s *SQLiteStore) Close() error {
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

func (s *SQLiteStore) Healthy() bool { return s != nil && s.healthError() == nil }

// Failure reports the first authoritative persistence error, if any.
// Callers use this to stop scheduling work rather than silently continuing.
func (s *SQLiteStore) Failure() error     { return s.healthError() }
func (s *SQLiteStore) healthError() error { s.mu.RLock(); defer s.mu.RUnlock(); return s.firstErr }
func (s *SQLiteStore) markUnhealthy(err error) {
	s.mu.Lock()
	if s.firstErr == nil {
		s.firstErr = fmt.Errorf("sqlite state store disabled after write failure: %w", err)
	}
	s.mu.Unlock()
}
func (s *SQLiteStore) restrictSidecars() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(s.path + suffix); err == nil {
			_ = os.Chmod(s.path+suffix, 0o600)
		}
	}
	return nil
}

func (s *SQLiteStore) BeginScan(id, version, semantics string, started time.Time) error {
	s.scanID = id
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO scans(scan_id,schema_version,snablr_version,semantics,started_at,status) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET snablr_version=excluded.snablr_version, semantics=excluded.semantics`, id, SchemaVersion, version, semantics, started.UTC().Format(time.RFC3339Nano), StatusRunning)
		return err
	})
}
func (s *SQLiteStore) SetScanStatus(status Status, ended time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE scans SET status=?, ended_at=? WHERE scan_id=?`, status, ended.UTC().Format(time.RFC3339Nano), s.scanID)
		return err
	})
}
func (s *SQLiteStore) RecordTarget(host, status string, at time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO targets(scan_id,host,status,updated_at) VALUES(?,?,?,?) ON CONFLICT(scan_id,host) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at`, s.scanID, host, status, at.UTC().Format(time.RFC3339Nano))
		return err
	})
}
func (s *SQLiteStore) RecordShare(host, share, status string, at time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO shares(scan_id,host,share,status,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(scan_id,host,share) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at`, s.scanID, host, share, status, at.UTC().Format(time.RFC3339Nano))
		return err
	})
}
func (s *SQLiteStore) RecordFile(key, host, share, path, status, semantics string, size int64, modifiedAt, firstSeen, lastSeen, updatedAt time.Time) error {
	f := FileState{Key: key, Host: host, Share: share, Path: path, Status: status, Semantics: semantics, Size: size, ModifiedAt: modifiedAt, FirstSeen: firstSeen, LastSeen: lastSeen, UpdatedAt: updatedAt}
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO files(scan_id,file_key,host,share,path,size,modified_at,first_seen,last_seen,updated_at,status,semantics) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scan_id,file_key) DO UPDATE SET size=excluded.size,modified_at=excluded.modified_at,last_seen=excluded.last_seen,updated_at=excluded.updated_at,status=excluded.status,semantics=excluded.semantics`, s.scanID, f.Key, f.Host, f.Share, f.Path, f.Size, timeString(f.ModifiedAt), timeString(f.FirstSeen), timeString(f.LastSeen), timeString(f.UpdatedAt), f.Status, f.Semantics)
		return err
	})
}
func (s *SQLiteStore) RecordAccess(contextID, fileKey, result string, first, last time.Time) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO access_observations(scan_id,context_id,file_key,first_seen,last_seen,access_result) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,context_id,file_key) DO UPDATE SET last_seen=excluded.last_seen,access_result=excluded.access_result`, s.scanID, contextID, fileKey, timeString(first), timeString(last), result)
		return err
	})
}
func (s *SQLiteStore) RecordMember(parent, member, kind, memberPath, status, provenance string) error {
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO members(scan_id,parent_key,member_key,member_type,member_path,status,provenance) VALUES(?,?,?,?,?,?,?) ON CONFLICT(scan_id,parent_key,member_key) DO UPDATE SET status=excluded.status,provenance=excluded.provenance`, s.scanID, parent, member, kind, memberPath, status, provenance)
		return err
	})
}
func (s *SQLiteStore) RecordFinding(f scanner.Finding) error {
	payload, _ := json.Marshal(f)
	digest := sha256.Sum256(payload)
	fingerprint := fmt.Sprintf("%x", digest[:])
	return s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO findings(scan_id,fingerprint,host,share,path,rule_id,category,payload) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scan_id,fingerprint) DO UPDATE SET payload=excluded.payload`, s.scanID, fingerprint, f.Host, f.Share, f.FilePath, f.RuleID, f.Category, payload)
		return err
	})
}
func (s *SQLiteStore) RecordCredential(c credentialanalysis.Candidate) error {
	payload, _ := credentialPayload(c)
	key := fmt.Sprintf("%s|%s|%s|%s", c.CredentialType, c.Identity, c.Path, c.Value)
	return s.enqueue(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO credentials(scan_id,credential_key,credential_type,identity,value,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,credential_key) DO UPDATE SET payload=excluded.payload,value=excluded.value`, s.scanID, key, c.CredentialType, c.Identity, c.Value, payload); err != nil {
			return err
		}
		return s.recordCredentialCorrelations(tx, c)
	})
}

func (s *SQLiteStore) recordCredentialCorrelations(tx *sql.Tx, candidate credentialanalysis.Candidate) error {
	if _, suppressed := credentialanalysis.SuppressionReason(candidate); suppressed || strings.TrimSpace(candidate.Identity) == "" || strings.TrimSpace(candidate.Path) == "" {
		return nil
	}
	rows, err := tx.Query(`SELECT payload,value FROM credentials WHERE scan_id=? AND credential_type=? AND lower(identity)=lower(?)`, s.scanID, candidate.CredentialType, candidate.Identity)
	if err != nil {
		return err
	}
	defer rows.Close()
	candidates := []credentialanalysis.Candidate{candidate}
	for rows.Next() {
		var payload []byte
		var value string
		var stored credentialanalysis.Candidate
		if err := rows.Scan(&payload, &value); err != nil {
			return err
		}
		if err := json.Unmarshal(payload, &stored); err != nil {
			continue
		}
		stored.Value = value
		candidates = append(candidates, stored)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, correlation := range credentialanalysis.Correlate(candidates) {
		payload, err := json.Marshal(correlation)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO correlations(scan_id,correlation_key,payload) VALUES(?,?,?) ON CONFLICT(scan_id,correlation_key) DO UPDATE SET payload=excluded.payload`, s.scanID, correlation.Key, payload); err != nil {
			return err
		}
	}
	return nil
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
func (s *SQLiteStore) RecordCorrelation(key string, payload any) error {
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

// SQLiteSink forwards output events while the owning scan monitors persistence
// health and applies its authority-specific failure policy.
type SQLiteSink struct {
	underlying scanner.FindingSink
	store      *SQLiteStore
}

func WrapSink(underlying scanner.FindingSink, stateStore *SQLiteStore) *SQLiteSink {
	return &SQLiteSink{underlying: underlying, store: stateStore}
}
func (s *SQLiteSink) WriteFinding(f scanner.Finding) error {
	if err := s.store.RecordFinding(f); err != nil {
	}
	return s.underlying.WriteFinding(f)
}
func (s *SQLiteSink) Close() error { return s.underlying.Close() }
func (s *SQLiteSink) RecordCredentialCandidate(c credentialanalysis.Candidate) error {
	_ = s.store.RecordCredential(c)
	if r, ok := s.underlying.(scanner.CredentialCandidateSink); ok {
		return r.RecordCredentialCandidate(c)
	}
	return nil
}
func (s *SQLiteSink) ExportNTDSCurrentHash(domain, account, source string, rid uint32, sid string, machine, disabled bool, hash []byte) error {
	if e, ok := s.underlying.(scanner.SensitiveCredentialExporter); ok {
		return e.ExportNTDSCurrentHash(domain, account, source, rid, sid, machine, disabled, hash)
	}
	return nil
}

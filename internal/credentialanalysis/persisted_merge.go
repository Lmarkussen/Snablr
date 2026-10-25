package credentialanalysis

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// PersistedMerger is the normalization/equivalence phase of Analyze backed by
// SQLite. Candidate values are encrypted with an ephemeral process key; the
// temporary database never stores plaintext credential values.
type PersistedMerger struct {
	db     *sql.DB
	path   string
	aead   cipher.AEAD
	key    []byte
	closed bool
	stats  PersistedMergeStats
}

// PersistedMergeStats mirrors the accounting fields produced by Analyze.
type PersistedMergeStats struct {
	CandidatesAnalyzed     int
	SuppressedPlaceholders int
	SuppressedWeakReview   int
	DuplicatesMerged       int
}

// PersistedMergedRecord is a bounded logical-credential summary. Membership
// is intentionally paged separately rather than reconstructed in this value.
type PersistedMergedRecord struct {
	ID            int64
	Candidate     Candidate
	EvidenceCount int
	LocationCount int
}

func NewPersistedMerger() (*PersistedMerger, error) {
	dir, err := os.MkdirTemp("", "snablr-credential-merge-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "merge.sqlite")
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;`); err != nil {
		_ = db.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE merged (id INTEGER PRIMARY KEY, record_key TEXT NOT NULL, correlation_group TEXT NOT NULL, credential_type TEXT NOT NULL, value_hash BLOB NOT NULL, payload BLOB NOT NULL, value_cipher BLOB NOT NULL);
CREATE INDEX merged_key_idx ON merged(record_key,id);
CREATE INDEX merged_lookup_idx ON merged(credential_type,value_hash,id);
CREATE INDEX merged_correlation_idx ON merged(correlation_group,record_key,id);
CREATE TABLE merged_evidence (merged_id INTEGER NOT NULL REFERENCES merged(id) ON DELETE CASCADE, rule_id TEXT NOT NULL, source TEXT NOT NULL, path TEXT NOT NULL, location TEXT NOT NULL, PRIMARY KEY(merged_id,rule_id,source,path,location));
CREATE TABLE merged_locations (merged_id INTEGER NOT NULL REFERENCES merged(id) ON DELETE CASCADE, location TEXT NOT NULL, PRIMARY KEY(merged_id,location));
CREATE INDEX merged_evidence_idx ON merged_evidence(merged_id,rule_id,path);
CREATE INDEX merged_locations_idx ON merged_locations(merged_id,location);
CREATE TABLE merged_observations (id INTEGER PRIMARY KEY, merged_id INTEGER NOT NULL REFERENCES merged(id) ON DELETE CASCADE, correlation_group TEXT NOT NULL, origin_key TEXT NOT NULL, payload BLOB NOT NULL, value_cipher BLOB NOT NULL);
CREATE INDEX merged_observations_corr_idx ON merged_observations(correlation_group,origin_key,id);`); err != nil {
		_ = db.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &PersistedMerger{db: db, path: path, aead: aead, key: key}, nil
}

func (m *PersistedMerger) Close() error {
	if m == nil {
		return nil
	}
	if m.closed {
		return nil
	}
	m.closed = true
	err := m.db.Close()
	for i := range m.key {
		m.key[i] = 0
	}
	m.key = nil
	m.aead = nil
	if removeErr := os.RemoveAll(filepath.Dir(m.path)); err == nil {
		err = removeErr
	}
	return err
}

func (m *PersistedMerger) DiskPath() string {
	if m == nil {
		return ""
	}
	return m.path
}

func (m *PersistedMerger) Add(ctx context.Context, candidate Candidate) error {
	if m == nil || m.db == nil || m.closed {
		return errors.New("persisted credential merger is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(candidate.CredentialType) == "" || (strings.TrimSpace(candidate.Value) == "" && candidate.Material != MaterialCorrelation) {
		return nil
	}
	m.stats.CandidatesAnalyzed++
	if reason, suppressed := SuppressionReason(candidate); suppressed {
		if reason == "placeholder" {
			m.stats.SuppressedPlaceholders++
		} else {
			m.stats.SuppressedWeakReview++
		}
		return nil
	}
	candidate = normalize(candidate)
	rows, err := m.db.QueryContext(ctx, `SELECT id,payload,value_cipher FROM merged WHERE credential_type=? AND value_hash=? ORDER BY record_key,id`, candidate.CredentialType, m.valueTag(candidate.Value))
	if err != nil {
		return err
	}
	var matchID int64
	var existing Candidate
	for rows.Next() {
		var id int64
		var payload, cipherText []byte
		if err := rows.Scan(&id, &payload, &cipherText); err != nil {
			_ = rows.Close()
			return err
		}
		stored, err := m.decode(payload, cipherText)
		if err != nil {
			_ = rows.Close()
			return err
		}
		if sameLogicalCredential(stored, candidate) {
			matchID, existing = id, stored
			break
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if matchID != 0 {
		m.stats.DuplicatesMerged++
		incoming := candidate
		candidate = mergeLogicalCredential(existing, candidate)
		return m.replace(ctx, matchID, candidate, incoming)
	}
	return m.insert(ctx, candidate)
}

func (m *PersistedMerger) Stats() PersistedMergeStats {
	if m == nil {
		return PersistedMergeStats{}
	}
	return m.stats
}

func (m *PersistedMerger) insert(ctx context.Context, candidate Candidate) error {
	payload, cipherText, err := m.encode(candidate)
	if err != nil {
		return err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO merged(record_key,correlation_group,credential_type,value_hash,payload,value_cipher) VALUES(?,?,?,?,?,?)`, recordKey(candidate), correlationGroupKey(candidate), candidate.CredentialType, m.valueTag(candidate.Value), payload, cipherText)
	if err == nil {
		var id int64
		id, err = result.LastInsertId()
		if err == nil {
			err = persistMembership(ctx, tx, id, candidate)
		}
		if err == nil {
			err = m.persistObservation(ctx, tx, id, candidate)
		}
	}
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
func (m *PersistedMerger) replace(ctx context.Context, id int64, candidate, observation Candidate) error {
	payload, cipherText, err := m.encode(candidate)
	if err != nil {
		return err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE merged SET record_key=?,correlation_group=?,credential_type=?,value_hash=?,payload=?,value_cipher=? WHERE id=?`, recordKey(candidate), correlationGroupKey(candidate), candidate.CredentialType, m.valueTag(candidate.Value), payload, cipherText, id)
	if err == nil {
		err = persistMembership(ctx, tx, id, candidate)
	}
	if err == nil {
		err = m.persistObservation(ctx, tx, id, observation)
	}
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
func (m *PersistedMerger) encode(candidate Candidate) ([]byte, []byte, error) {
	// Membership is stored separately so a large duplicate group does not
	// rewrite or retain its complete origin/evidence arrays in the summary row.
	candidate.Evidence = nil
	candidate.Locations = nil
	payload, err := json.Marshal(candidate)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return payload, m.aead.Seal(nonce, nonce, []byte(candidate.Value), nil), nil
}

func (m *PersistedMerger) encodeObservation(candidate Candidate) ([]byte, []byte, error) {
	payload, err := json.Marshal(candidate)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return payload, m.aead.Seal(nonce, nonce, []byte(candidate.Value), nil), nil
}

func (m *PersistedMerger) valueTag(value string) []byte {
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func correlationGroupKey(candidate Candidate) string {
	identity := strings.TrimSpace(candidate.Identity)
	credentialType := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	if identity == "" || IsPlaceholderIdentity(identity) || credentialType == "" || strings.TrimSpace(candidate.Path) == "" {
		return ""
	}
	return strings.Join([]string{strings.ToLower(strings.TrimSpace(candidate.Domain)), strings.ToLower(identity), credentialType}, "\x00")
}

func persistMembership(ctx context.Context, tx *sql.Tx, id int64, candidate Candidate) error {
	for _, evidence := range candidate.Evidence {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO merged_evidence(merged_id,rule_id,source,path,location) VALUES(?,?,?,?,?)`, id, evidence.RuleID, evidence.Source, evidence.Path, evidence.Location); err != nil {
			return err
		}
	}
	for _, location := range candidate.Locations {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO merged_locations(merged_id,location) VALUES(?,?)`, id, location); err != nil {
			return err
		}
	}
	return nil
}

func (m *PersistedMerger) persistObservation(ctx context.Context, tx *sql.Tx, mergedID int64, candidate Candidate) error {
	payload, cipherText, err := m.encodeObservation(candidate)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO merged_observations(merged_id,correlation_group,origin_key,payload,value_cipher) VALUES(?,?,?,?,?)`, mergedID, correlationGroupKey(candidate), candidateOrigin(candidate), payload, cipherText)
	return err
}
func (m *PersistedMerger) decode(payload, cipherText []byte) (Candidate, error) {
	var candidate Candidate
	if err := json.Unmarshal(payload, &candidate); err != nil {
		return candidate, err
	}
	nonceSize := m.aead.NonceSize()
	if len(cipherText) < nonceSize {
		return candidate, errors.New("invalid encrypted credential value")
	}
	value, err := m.aead.Open(nil, cipherText[:nonceSize], cipherText[nonceSize:], nil)
	if err != nil {
		return candidate, err
	}
	candidate.Value = string(value)
	return candidate, nil
}

func (m *PersistedMerger) Count(ctx context.Context) (int, error) {
	if m == nil || m.db == nil || m.closed {
		return 0, errors.New("persisted credential merger is closed")
	}
	var n int
	err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM merged`).Scan(&n)
	return n, err
}
func (m *PersistedMerger) Iterate(ctx context.Context, visit func(Candidate) error) error {
	if visit == nil {
		return errors.New("persisted credential merger visitor is nil")
	}
	return m.IterateRecords(ctx, func(record PersistedMergedRecord) error {
		candidate := record.Candidate
		if err := m.loadMembership(ctx, record.ID, &candidate); err != nil {
			return err
		}
		return visit(candidate)
	})
}

// IterateRecords visits compact summaries in stable order. It never loads
// membership arrays; use the page methods to expand one record on demand.
func (m *PersistedMerger) IterateRecords(ctx context.Context, visit func(PersistedMergedRecord) error) error {
	if m == nil || m.db == nil || m.closed {
		return errors.New("persisted credential merger is closed")
	}
	if visit == nil {
		return errors.New("persisted credential merger visitor is nil")
	}
	rows, err := m.db.QueryContext(ctx, `SELECT id,payload,value_cipher,(SELECT COUNT(*) FROM merged_evidence WHERE merged_id=merged.id),(SELECT COUNT(*) FROM merged_locations WHERE merged_id=merged.id) FROM merged ORDER BY record_key,id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var id int64
		var payload, cipherText []byte
		var evidenceCount, locationCount int
		if err := rows.Scan(&id, &payload, &cipherText, &evidenceCount, &locationCount); err != nil {
			return err
		}
		candidate, err := m.decode(payload, cipherText)
		if err != nil {
			return err
		}
		candidate.Evidence = []Evidence{}
		candidate.Locations = []string{}
		if err := visit(PersistedMergedRecord{ID: id, Candidate: candidate, EvidenceCount: evidenceCount, LocationCount: locationCount}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// EvidenceCursor and LocationCursor are opaque continuation positions for
// bounded membership expansion.
type EvidenceCursor struct {
	Valid                          bool
	RuleID, Source, Path, Location string
}

type LocationCursor struct {
	Valid    bool
	Location string
}

func (m *PersistedMerger) IterateEvidencePage(ctx context.Context, id int64, cursor EvidenceCursor, limit int, visit func(Evidence) error) (EvidenceCursor, bool, error) {
	if limit <= 0 {
		return cursor, false, errors.New("evidence page size must be positive")
	}
	if m == nil || m.db == nil || m.closed {
		return cursor, false, errors.New("persisted credential merger is closed")
	}
	query := `SELECT rule_id,source,path,location FROM merged_evidence WHERE merged_id=? ORDER BY rule_id,source,path,location LIMIT ?`
	args := []any{id, limit + 1}
	if cursor.Valid {
		query = `SELECT rule_id,source,path,location FROM merged_evidence WHERE merged_id=? AND (rule_id>? OR (rule_id=? AND source>?) OR (rule_id=? AND source=? AND path>?) OR (rule_id=? AND source=? AND path=? AND location>?)) ORDER BY rule_id,source,path,location LIMIT ?`
		args = []any{id, cursor.RuleID, cursor.RuleID, cursor.Source, cursor.RuleID, cursor.Source, cursor.Path, cursor.RuleID, cursor.Source, cursor.Path, cursor.Location, limit + 1}
	}
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return cursor, false, err
	}
	defer rows.Close()
	last := cursor
	count := 0
	more := false
	for rows.Next() {
		var evidence Evidence
		if err := rows.Scan(&evidence.RuleID, &evidence.Source, &evidence.Path, &evidence.Location); err != nil {
			return last, false, err
		}
		count++
		if count > limit {
			more = true
			break
		}
		if err := ctx.Err(); err != nil {
			return last, false, err
		}
		if err := visit(evidence); err != nil {
			return last, false, err
		}
		last = EvidenceCursor{Valid: true, RuleID: evidence.RuleID, Source: evidence.Source, Path: evidence.Path, Location: evidence.Location}
	}
	return last, more, rows.Err()
}

func (m *PersistedMerger) IterateLocationPage(ctx context.Context, id int64, cursor LocationCursor, limit int, visit func(string) error) (LocationCursor, bool, error) {
	if limit <= 0 {
		return cursor, false, errors.New("location page size must be positive")
	}
	if m == nil || m.db == nil || m.closed {
		return cursor, false, errors.New("persisted credential merger is closed")
	}
	query := `SELECT location FROM merged_locations WHERE merged_id=? ORDER BY location LIMIT ?`
	args := []any{id, limit + 1}
	if cursor.Valid {
		query = `SELECT location FROM merged_locations WHERE merged_id=? AND location>? ORDER BY location LIMIT ?`
		args = []any{id, cursor.Location, limit + 1}
	}
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return cursor, false, err
	}
	defer rows.Close()
	last := cursor
	count := 0
	more := false
	for rows.Next() {
		var location string
		if err := rows.Scan(&location); err != nil {
			return last, false, err
		}
		count++
		if count > limit {
			more = true
			break
		}
		if err := ctx.Err(); err != nil {
			return last, false, err
		}
		if err := visit(location); err != nil {
			return last, false, err
		}
		last = LocationCursor{Valid: true, Location: location}
	}
	return last, more, rows.Err()
}

// IterateCorrelations processes one persisted identity/type group at a time.
// The legacy Correlate predicate remains authoritative; only its input
// population and output are moved through the temporary SQLite state.
func (m *PersistedMerger) IterateCorrelations(ctx context.Context, visit func(Correlation) error) error {
	if m == nil || m.db == nil || m.closed {
		return errors.New("persisted credential merger is closed")
	}
	if visit == nil {
		return errors.New("persisted credential correlation visitor is nil")
	}
	rows, err := m.db.QueryContext(ctx, `SELECT id,payload,value_cipher,correlation_group FROM merged_observations WHERE correlation_group<>'' ORDER BY correlation_group,origin_key,id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	groupKey := ""
	var group []Candidate
	flush := func() error {
		if len(group) == 0 {
			return nil
		}
		for _, correlation := range Correlate(group) {
			if err := visit(correlation); err != nil {
				return err
			}
		}
		group = nil
		return nil
	}
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var id int64
		var payload, cipherText []byte
		var currentGroup string
		if err := rows.Scan(&id, &payload, &cipherText, &currentGroup); err != nil {
			return err
		}
		if groupKey != "" && currentGroup != groupKey {
			if err := flush(); err != nil {
				return err
			}
		}
		groupKey = currentGroup
		candidate, err := m.decode(payload, cipherText)
		if err != nil {
			return err
		}
		group = append(group, candidate)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
}

func (m *PersistedMerger) loadMembership(ctx context.Context, id int64, candidate *Candidate) error {
	candidate.Evidence = make([]Evidence, 0)
	candidate.Locations = make([]string, 0)
	evidenceRows, err := m.db.QueryContext(ctx, `SELECT rule_id,source,path,location FROM merged_evidence WHERE merged_id=? ORDER BY rule_id,path,location`, id)
	if err != nil {
		return err
	}
	defer evidenceRows.Close()
	for evidenceRows.Next() {
		var evidence Evidence
		if err := evidenceRows.Scan(&evidence.RuleID, &evidence.Source, &evidence.Path, &evidence.Location); err != nil {
			return err
		}
		candidate.Evidence = append(candidate.Evidence, evidence)
	}
	if err := evidenceRows.Err(); err != nil {
		return err
	}
	locationRows, err := m.db.QueryContext(ctx, `SELECT location FROM merged_locations WHERE merged_id=? ORDER BY location`, id)
	if err != nil {
		return err
	}
	defer locationRows.Close()
	for locationRows.Next() {
		var location string
		if err := locationRows.Scan(&location); err != nil {
			return err
		}
		candidate.Locations = append(candidate.Locations, location)
	}
	return locationRows.Err()
}

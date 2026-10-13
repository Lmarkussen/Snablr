package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// ResumeOptions controls an explicitly opt-in SQLite resume open.
type ResumeOptions struct {
	ScanID            string
	ExpectedSemantics string
	MaterializeFiles  bool
	QueueSize         int
	BatchSize         int
	FlushEvery        time.Duration
}

type TargetState struct {
	Host, Status string
}

type ShareState struct {
	Host, Share, Status string
}

type MemberState struct {
	ParentKey, MemberKey, MemberType, MemberPath, Status, Provenance string
}

type AccessState struct {
	ContextID, FileKey, Result string
	FirstSeen, LastSeen        time.Time
}

// ResumeState is a logical view of one persisted scan. It deliberately keeps
// database details out of callers and contains no remote file contents.
type ResumeState struct {
	ScanID, SchemaVersion, SnablrVersion, Semantics, Status string
	SemanticsMatch                                          bool
	FilesMaterialized                                       bool
	StartedAt, EndedAt                                      time.Time
	Targets                                                 []TargetState
	Shares                                                  []ShareState
	Files                                                   []FileState
	Members                                                 []MemberState
	Access                                                  []AccessState
	Findings                                                []scanner.Finding
	Credentials                                             []credentialanalysis.Candidate
	Correlations                                            map[string]json.RawMessage
}

// OpenForResume validates and reopens an existing SQLite scan. The returned
// store writes to the same scan row; it never creates a new scan row.
func OpenForResume(path string, options ResumeOptions) (*SQLiteStore, ResumeState, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ResumeState{}, fmt.Errorf("sqlite resume state path cannot be empty")
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, ResumeState{}, fmt.Errorf("open sqlite resume state: %w", err)
	}
	cleanup := func(e error) (*SQLiteStore, ResumeState, error) { _ = db.Close(); return nil, ResumeState{}, e }
	for _, pragma := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(pragma); err != nil {
			return cleanup(fmt.Errorf("configure sqlite resume state: %w", err))
		}
	}
	if err := validateExistingSchema(db); err != nil {
		return cleanup(err)
	}
	var state ResumeState
	if err := loadResumeState(db, options.ScanID, options.MaterializeFiles, &state); err != nil {
		return cleanup(err)
	}
	if strings.TrimSpace(state.Semantics) == "" {
		return cleanup(fmt.Errorf("sqlite resume scan %s is missing semantics metadata", state.ScanID))
	}
	state.SemanticsMatch = strings.TrimSpace(options.ExpectedSemantics) == "" || state.Semantics == strings.TrimSpace(options.ExpectedSemantics)
	_ = db.Close()
	stateStore, err := Open(path, Options{ScanID: state.ScanID, SnablrVersion: state.SnablrVersion, Semantics: state.Semantics, QueueSize: options.QueueSize, BatchSize: options.BatchSize, FlushEvery: options.FlushEvery})
	if err != nil {
		return nil, ResumeState{}, err
	}
	if err := stateStore.SetScanStatus(StatusRunning, time.Now().UTC()); err != nil {
		_ = stateStore.Close()
		return nil, ResumeState{}, err
	}
	return stateStore, state, nil
}

func validateExistingSchema(db *sql.DB) error {
	var version string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sqlite resume state is missing schema metadata")
		}
		return fmt.Errorf("read sqlite resume schema metadata: %w", err)
	}
	if version != fmt.Sprintf("%d", SchemaVersion) {
		return fmt.Errorf("unsupported SQLite scan database schema version %s", version)
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("check sqlite resume state integrity: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("sqlite resume state integrity check failed: %s", integrity)
	}
	return nil
}

func loadResumeState(db *sql.DB, requestedID string, materializeFiles bool, out *ResumeState) error {
	out.FilesMaterialized = materializeFiles
	query := `SELECT scan_id,schema_version,snablr_version,semantics,started_at,ended_at,status FROM scans WHERE scan_id=?`
	args := []any{requestedID}
	if strings.TrimSpace(requestedID) == "" {
		query = `SELECT scan_id,schema_version,snablr_version,semantics,started_at,ended_at,status FROM scans ORDER BY started_at DESC LIMIT 1`
		args = nil
	}
	var schema int
	var started, status string
	var ended sql.NullString
	if err := db.QueryRow(query, args...).Scan(&out.ScanID, &schema, &out.SnablrVersion, &out.Semantics, &started, &ended, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("sqlite resume state contains no scan")
		}
		return fmt.Errorf("load sqlite scan metadata: %w", err)
	}
	if schema != SchemaVersion {
		return fmt.Errorf("unsupported sqlite scan schema version %d", schema)
	}
	out.SchemaVersion, out.Status = fmt.Sprintf("%d", schema), status
	out.StartedAt = parseTime(started)
	out.EndedAt = parseNullableTime(ended)
	if strings.TrimSpace(out.Semantics) == "" {
		return fmt.Errorf("sqlite scan %s is missing semantics metadata", out.ScanID)
	}
	rows, err := db.Query(`SELECT host,status FROM targets WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v TargetState
		if err := rows.Scan(&v.Host, &v.Status); err != nil {
			rows.Close()
			return err
		}
		out.Targets = append(out.Targets, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = db.Query(`SELECT host,share,status FROM shares WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v ShareState
		if err := rows.Scan(&v.Host, &v.Share, &v.Status); err != nil {
			rows.Close()
			return err
		}
		out.Shares = append(out.Shares, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if materializeFiles {
		rows, err = db.Query(`SELECT file_key,host,share,path,status,semantics,size,modified_at,first_seen,last_seen,updated_at FROM files WHERE scan_id=?`, out.ScanID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var v FileState
			var modified, first, last, updated sql.NullString
			if err := rows.Scan(&v.Key, &v.Host, &v.Share, &v.Path, &v.Status, &v.Semantics, &v.Size, &modified, &first, &last, &updated); err != nil {
				rows.Close()
				return err
			}
			v.ModifiedAt = parseNullableTime(modified)
			v.FirstSeen = parseNullableTime(first)
			v.LastSeen = parseNullableTime(last)
			v.UpdatedAt = parseNullableTime(updated)
			out.Files = append(out.Files, v)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	rows, err = db.Query(`SELECT parent_key,member_key,member_type,member_path,status,provenance FROM members WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v MemberState
		var provenance sql.NullString
		if err := rows.Scan(&v.ParentKey, &v.MemberKey, &v.MemberType, &v.MemberPath, &v.Status, &provenance); err != nil {
			rows.Close()
			return err
		}
		v.Provenance = provenance.String
		out.Members = append(out.Members, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = db.Query(`SELECT context_id,file_key,first_seen,last_seen,access_result FROM access_observations WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v AccessState
		var first, last string
		if err := rows.Scan(&v.ContextID, &v.FileKey, &first, &last, &v.Result); err != nil {
			rows.Close()
			return err
		}
		v.FirstSeen = parseTime(first)
		v.LastSeen = parseTime(last)
		out.Access = append(out.Access, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = db.Query(`SELECT payload FROM findings WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var payload []byte
		var f scanner.Finding
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(payload, &f); err != nil {
			rows.Close()
			return fmt.Errorf("decode sqlite finding: %w", err)
		}
		out.Findings = append(out.Findings, f)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = db.Query(`SELECT payload FROM credentials WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var payload []byte
		var c credentialanalysis.Candidate
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal(payload, &c); err != nil {
			rows.Close()
			return fmt.Errorf("decode sqlite credential: %w", err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(payload, &object); err == nil {
			_ = json.Unmarshal(object["value"], &c.Value)
		}
		out.Credentials = append(out.Credentials, c)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	out.Correlations = map[string]json.RawMessage{}
	rows, err = db.Query(`SELECT correlation_key,payload FROM correlations WHERE scan_id=?`, out.ScanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		var payload []byte
		if err := rows.Scan(&key, &payload); err != nil {
			rows.Close()
			return err
		}
		out.Correlations[key] = json.RawMessage(payload)
	}
	return rows.Close()
}

// LookupFile returns one persisted file row without materializing the scan's
// complete inventory. It is intended for the experimental lazy resume path.
func (s *SQLiteStore) LookupFile(host, share, path string) (FileState, bool, error) {
	if s == nil || s.db == nil {
		return FileState{}, false, fmt.Errorf("sqlite resume store is closed")
	}
	var file FileState
	var modified, first, last, updated sql.NullString
	err := s.db.QueryRow(`SELECT file_key,host,share,path,status,semantics,size,modified_at,first_seen,last_seen,updated_at FROM files WHERE scan_id=? AND host=? AND share=? AND path=?`, s.scanID, host, share, path).Scan(&file.Key, &file.Host, &file.Share, &file.Path, &file.Status, &file.Semantics, &file.Size, &modified, &first, &last, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return FileState{}, false, nil
	}
	if err != nil {
		return FileState{}, false, err
	}
	file.ModifiedAt, file.FirstSeen, file.LastSeen, file.UpdatedAt = parseNullableTime(modified), parseNullableTime(first), parseNullableTime(last), parseNullableTime(updated)
	return file, true, nil
}

func (s *SQLiteStore) ResumeTargetComplete(host string) (bool, error) {
	var status string
	err := s.db.QueryRow(`SELECT status FROM targets WHERE scan_id=? AND host=?`, s.scanID, host).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return status == "completed", err
}

func (s *SQLiteStore) ResumeShareComplete(host, share string) (bool, error) {
	var status string
	err := s.db.QueryRow(`SELECT status FROM shares WHERE scan_id=? AND host=? AND share=?`, s.scanID, host, share).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return status == "completed", err
}

func (s *SQLiteStore) RemainingFileCount() (int64, error) {
	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM files WHERE scan_id=? AND status NOT IN ('completed','skipped_unchanged')`, s.scanID).Scan(&count)
	return count, err
}

func parseNullableTime(value sql.NullString) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return parseTime(value.String)
}
func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, value)
	return t
}

// FileWasCompleted reports whether a file identity was safely reusable at the
// time the state was loaded. It is used to avoid replaying results belonging
// to incomplete work items.
func (s ResumeState) FileWasCompleted(host, share, path string) bool {
	if !s.FilesMaterialized {
		return true
	}
	for _, file := range s.Files {
		if file.Status != "completed" && file.Status != "skipped_unchanged" {
			continue
		}
		if strings.EqualFold(file.Host, host) && strings.EqualFold(file.Share, share) && file.Path == path {
			return s.SemanticsMatch
		}
	}
	return false
}

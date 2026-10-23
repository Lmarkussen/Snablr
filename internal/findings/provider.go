package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

const (
	SchemaVersion  = 2
	PageSize       = 500
	LoadBatchPages = 8
)

type Provider struct {
	db            *sql.DB
	path          string
	hasDisplayIDs bool
}

type Scan struct {
	ID, DisplayID, Version, Semantics, Status string
	Targets                                   string
	Started, Ended                            time.Time
	FindingCount                              int
}

type Finding struct {
	ID          int64
	Fingerprint string
	Finding     scanner.Finding
}

type Credential struct {
	ID            int64
	CredentialKey string
	Candidate     credentialanalysis.Candidate
}

type Correlation struct {
	Key     string
	Payload string
}

func Open(path string) (*Provider, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("findings database path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve findings database path %q: %w", path, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("findings database does not exist: %s", absolute)
		}
		return nil, fmt.Errorf("inspect findings database %s: %w", absolute, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("findings database path is a directory: %s", absolute)
	}

	db, err := sql.Open("sqlite3", "file:"+absolute+"?mode=ro&_query_only=1&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open findings database read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	cleanup := func(cause error) (*Provider, error) {
		_ = db.Close()
		return nil, cause
	}
	var version string
	if err := db.QueryRow(`SELECT value FROM metadata WHERE key='schema_version'`).Scan(&version); err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return cleanup(fmt.Errorf("findings database %s is not a Snablr SQLite database", absolute))
		}
		return cleanup(fmt.Errorf("read findings database schema: %w", err))
	}
	if version != fmt.Sprintf("%d", SchemaVersion) {
		return cleanup(fmt.Errorf("unsupported Snablr SQLite schema version %s (expected %d)", version, SchemaVersion))
	}
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return cleanup(fmt.Errorf("check findings database integrity: %w", err))
	}
	if integrity != "ok" {
		return cleanup(fmt.Errorf("findings database integrity check failed: %s", integrity))
	}
	var displayTable int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='scan_labels'`).Scan(&displayTable); err != nil {
		return cleanup(fmt.Errorf("inspect findings database tables: %w", err))
	}
	return &Provider{db: db, path: absolute, hasDisplayIDs: displayTable != 0}, nil
}

func (p *Provider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *Provider) Path() string { return p.path }

func (p *Provider) ListScans(ctx context.Context) ([]Scan, error) {
	query := `
SELECT s.scan_id, s.scan_id, COALESCE(s.snablr_version,''), COALESCE(s.semantics,''), s.status,
       s.started_at, COALESCE(s.ended_at,''),
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.scan_id),
       COALESCE((SELECT group_concat(t.host, ', ') FROM targets t WHERE t.scan_id=s.scan_id), '')
FROM scans s ORDER BY s.started_at DESC`
	if p.hasDisplayIDs {
		query = `
SELECT s.scan_id, COALESCE(l.display_id,s.scan_id), COALESCE(s.snablr_version,''), COALESCE(s.semantics,''), s.status,
       s.started_at, COALESCE(s.ended_at,''),
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.scan_id),
       COALESCE((SELECT group_concat(t.host, ', ') FROM targets t WHERE t.scan_id=s.scan_id), '')
FROM scans s LEFT JOIN scan_labels l ON l.scan_id=s.scan_id ORDER BY s.started_at DESC`
	}
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list persisted scans: %w", err)
	}
	defer rows.Close()
	var scans []Scan
	for rows.Next() {
		var scan Scan
		var started, ended string
		if err := rows.Scan(&scan.ID, &scan.DisplayID, &scan.Version, &scan.Semantics, &scan.Status, &started, &ended, &scan.FindingCount, &scan.Targets); err != nil {
			return nil, fmt.Errorf("read persisted scan metadata: %w", err)
		}
		scan.Started = parseTime(started)
		scan.Ended = parseTime(ended)
		scans = append(scans, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted scans: %w", err)
	}
	return scans, nil
}

func (p *Provider) Findings(ctx context.Context, scanID string, offset, limit int) ([]Finding, error) {
	if offset < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid findings page bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,fingerprint,payload FROM findings WHERE scan_id=? ORDER BY id LIMIT ? OFFSET ?`, scanID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("read persisted findings: %w", err)
	}
	defer rows.Close()
	result := make([]Finding, 0, limit)
	for rows.Next() {
		var item Finding
		var payload string
		if err := rows.Scan(&item.ID, &item.Fingerprint, &payload); err != nil {
			return nil, fmt.Errorf("read persisted finding row: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &item.Finding); err != nil {
			return nil, fmt.Errorf("decode persisted finding %d: %w", item.ID, err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted findings: %w", err)
	}
	return result, nil
}

func (p *Provider) Finding(ctx context.Context, scanID string, id int64) (Finding, error) {
	var item Finding
	var payload string
	if err := p.db.QueryRowContext(ctx, `SELECT id,fingerprint,payload FROM findings WHERE scan_id=? AND id=?`, scanID, id).Scan(&item.ID, &item.Fingerprint, &payload); err != nil {
		return Finding{}, fmt.Errorf("read persisted finding %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(payload), &item.Finding); err != nil {
		return Finding{}, fmt.Errorf("decode persisted finding %d: %w", id, err)
	}
	return item, nil
}

func (p *Provider) Credentials(ctx context.Context, scanID string, offset, limit int) ([]Credential, error) {
	if offset < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid credentials page bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? ORDER BY id LIMIT ? OFFSET ?`, scanID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("read persisted credentials: %w", err)
	}
	defer rows.Close()
	result := make([]Credential, 0, limit)
	for rows.Next() {
		var item Credential
		var payload string
		if err := rows.Scan(&item.ID, &item.CredentialKey, &payload); err != nil {
			return nil, fmt.Errorf("read persisted credential row: %w", err)
		}
		if err := json.Unmarshal([]byte(payload), &item.Candidate); err != nil {
			return nil, fmt.Errorf("decode persisted credential %d: %w", item.ID, err)
		}
		var raw struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal([]byte(payload), &raw); err == nil {
			item.Candidate.Value = raw.Value
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted credentials: %w", err)
	}
	return result, nil
}

func (p *Provider) Credential(ctx context.Context, scanID, key string) (Credential, error) {
	var item Credential
	var payload string
	if err := p.db.QueryRowContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? AND credential_key=?`, scanID, key).Scan(&item.ID, &item.CredentialKey, &payload); err != nil {
		return Credential{}, fmt.Errorf("read persisted credential %q: %w", key, err)
	}
	if err := json.Unmarshal([]byte(payload), &item.Candidate); err != nil {
		return Credential{}, fmt.Errorf("decode persisted credential %q: %w", key, err)
	}
	return item, nil
}

func (p *Provider) Correlations(ctx context.Context, scanID string, offset, limit int) ([]Correlation, error) {
	if offset < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid correlations page bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT correlation_key,payload FROM correlations WHERE scan_id=? ORDER BY correlation_key LIMIT ? OFFSET ?`, scanID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("read persisted correlations: %w", err)
	}
	defer rows.Close()
	result := make([]Correlation, 0, limit)
	for rows.Next() {
		var item Correlation
		if err := rows.Scan(&item.Key, &item.Payload); err != nil {
			return nil, fmt.Errorf("read persisted correlation row: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted correlations: %w", err)
	}
	return result, nil
}

func (p *Provider) Correlation(ctx context.Context, scanID, key string) (Correlation, error) {
	var item Correlation
	if err := p.db.QueryRowContext(ctx, `SELECT correlation_key,payload FROM correlations WHERE scan_id=? AND correlation_key=?`, scanID, key).Scan(&item.Key, &item.Payload); err != nil {
		return Correlation{}, fmt.Errorf("read persisted correlation %q: %w", key, err)
	}
	return item, nil
}

// SearchRefs returns stable persisted-row references whose source metadata or
// raw payload matches query. It keeps evidence in SQLite while preserving
// Finder's evidence-first search behavior after metadata compaction.
func (p *Provider) SearchRefs(ctx context.Context, scanID, query string) (map[string]struct{}, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	rows, err := p.db.QueryContext(ctx, `
SELECT 'finding:' || id FROM findings
 WHERE scan_id=? AND (instr(payload,?)>0 OR instr(path,?)>0 OR instr(rule_id,?)>0)
UNION ALL
SELECT credential_key FROM credentials
 WHERE scan_id=? AND (instr(payload,?)>0 OR instr(credential_key,?)>0 OR instr(identity,?)>0 OR instr(value,?)>0)
UNION ALL
SELECT 'correlation:' || correlation_key FROM correlations
 WHERE scan_id=? AND instr(payload,?)>0`,
		scanID, query, query, query,
		scanID, query, query, query, query,
		scanID, query)
	if err != nil {
		return nil, fmt.Errorf("search persisted evidence: %w", err)
	}
	defer rows.Close()
	refs := make(map[string]struct{})
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, fmt.Errorf("read persisted evidence search result: %w", err)
		}
		refs[ref] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted evidence search results: %w", err)
	}
	return refs, nil
}

func parseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

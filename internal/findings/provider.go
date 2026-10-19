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
	"snablr/internal/scanner"
)

const (
	SchemaVersion = 2
	PageSize      = 500
)

type Provider struct {
	db   *sql.DB
	path string
}

type Scan struct {
	ID, Version, Semantics, Status string
	Targets                        string
	Started, Ended                 time.Time
	FindingCount                   int
}

type Finding struct {
	ID          int64
	Fingerprint string
	Finding     scanner.Finding
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
	return &Provider{db: db, path: absolute}, nil
}

func (p *Provider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *Provider) Path() string { return p.path }

func (p *Provider) ListScans(ctx context.Context) ([]Scan, error) {
	rows, err := p.db.QueryContext(ctx, `
SELECT s.scan_id, COALESCE(s.snablr_version,''), COALESCE(s.semantics,''), s.status,
       s.started_at, COALESCE(s.ended_at,''),
       (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.scan_id),
       COALESCE((SELECT group_concat(t.host, ', ') FROM targets t WHERE t.scan_id=s.scan_id), '')
FROM scans s ORDER BY s.started_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list persisted scans: %w", err)
	}
	defer rows.Close()
	var scans []Scan
	for rows.Next() {
		var scan Scan
		var started, ended string
		if err := rows.Scan(&scan.ID, &scan.Version, &scan.Semantics, &scan.Status, &started, &ended, &scan.FindingCount, &scan.Targets); err != nil {
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

func parseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

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
	SchemaVersion              = 2
	PageSize                   = 500
	LoadBatchPages             = 8
	derivedFindingIDBase int64 = 1 << 62
)

type Provider struct {
	db                 *sql.DB
	path               string
	hasDisplayIDs      bool
	hasDerivedFindings bool
}

type Scan struct {
	ID, DisplayID, Version, Semantics, Status string    `json:"-"`
	Targets                                   string    `json:"targets"`
	Started, Ended                            time.Time `json:"-"`
	FindingCount                              int       `json:"finding_count"`
}

type ScanCounts struct {
	Findings     int
	Credentials  int
	Correlations int
}

type SearchPage struct {
	Findings          []Finding
	Credentials       []Credential
	Correlations      []Correlation
	PersistedRows     int
	FindingCursor     int64
	CredentialCursor  int64
	CorrelationCursor string
	Done              bool
}

type Finding struct {
	ID          int64
	Fingerprint string
	Finding     scanner.Finding
	Derived     bool
}

func (f Finding) StableID() string {
	if f.Derived {
		return "derived:" + f.Fingerprint
	}
	return fmt.Sprintf("finding:%d", f.ID)
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
	if version != "2" && version != "3" {
		return cleanup(fmt.Errorf("unsupported Snablr SQLite schema version %s (expected 2 or 3)", version))
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
	var derivedTable, derivedStateTable int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='derived_findings'`).Scan(&derivedTable); err != nil {
		return cleanup(fmt.Errorf("inspect derived findings table: %w", err))
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='derived_state'`).Scan(&derivedStateTable); err != nil {
		return cleanup(fmt.Errorf("inspect derived state table: %w", err))
	}
	return &Provider{db: db, path: absolute, hasDisplayIDs: displayTable != 0, hasDerivedFindings: derivedTable != 0 && derivedStateTable != 0}, nil
}

func (p *Provider) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *Provider) Path() string { return p.path }

func (p *Provider) Counts(ctx context.Context, scanID string) (ScanCounts, error) {
	var counts ScanCounts
	queries := []*int{&counts.Credentials, &counts.Correlations}
	for index, table := range []string{"credentials", "correlations"} {
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE scan_id=?", scanID).Scan(queries[index]); err != nil {
			return ScanCounts{}, fmt.Errorf("count persisted %s: %w", table, err)
		}
	}
	var err error
	if p.hasDerivedFindings {
		err = p.db.QueryRowContext(ctx, p.findingCountQuery(), scanID, scanID).Scan(&counts.Findings)
	} else {
		err = p.db.QueryRowContext(ctx, p.findingCountQuery(), scanID).Scan(&counts.Findings)
	}
	if err != nil {
		return ScanCounts{}, fmt.Errorf("count persisted findings: %w", err)
	}
	return counts, nil
}

func (p *Provider) findingCountQuery() string {
	if !p.hasDerivedFindings {
		return `SELECT COUNT(*) FROM findings WHERE scan_id=?`
	}
	return `SELECT (SELECT COUNT(*) FROM findings WHERE scan_id=?) + (SELECT COUNT(*) FROM derived_findings d WHERE d.scan_id=? AND EXISTS (SELECT 1 FROM derived_state s WHERE s.scan_id=d.scan_id AND s.status='complete'))`
}

func (p *Provider) findingRowsQuery(selectClause, predicate string) string {
	if !p.hasDerivedFindings {
		if strings.HasPrefix(predicate, "ORDER ") {
			return `SELECT ` + selectClause + ` FROM findings WHERE scan_id=? ` + predicate
		}
		return `SELECT ` + selectClause + ` FROM findings WHERE scan_id=? AND ` + strings.TrimPrefix(predicate, "WHERE ")
	}
	if strings.HasPrefix(predicate, "WHERE ") {
		return `SELECT ` + selectClause + ` FROM (SELECT id,fingerprint,payload,path,rule_id FROM findings WHERE scan_id=? UNION ALL SELECT ` + fmt.Sprintf("%d", derivedFindingIDBase) + `+d.id, 'derived:'||d.correlation_key, d.payload, json_extract(d.payload,'$.file_path'), json_extract(d.payload,'$.rule_id') FROM derived_findings d WHERE d.scan_id=? AND EXISTS (SELECT 1 FROM derived_state s WHERE s.scan_id=d.scan_id AND s.status='complete')) rows ` + predicate
	}
	if strings.HasPrefix(predicate, "ORDER ") {
		return `SELECT ` + selectClause + ` FROM (SELECT id,fingerprint,payload,path,rule_id FROM findings WHERE scan_id=? UNION ALL SELECT ` + fmt.Sprintf("%d", derivedFindingIDBase) + `+d.id, 'derived:'||d.correlation_key, d.payload, json_extract(d.payload,'$.file_path'), json_extract(d.payload,'$.rule_id') FROM derived_findings d WHERE d.scan_id=? AND EXISTS (SELECT 1 FROM derived_state s WHERE s.scan_id=d.scan_id AND s.status='complete')) rows ` + predicate
	}
	return `SELECT ` + selectClause + ` FROM (SELECT id,fingerprint,payload,path,rule_id FROM findings WHERE scan_id=? UNION ALL SELECT ` + fmt.Sprintf("%d", derivedFindingIDBase) + `+d.id, 'derived:'||d.correlation_key, d.payload, json_extract(d.payload,'$.file_path'), json_extract(d.payload,'$.rule_id') FROM derived_findings d WHERE d.scan_id=? AND EXISTS (SELECT 1 FROM derived_state s WHERE s.scan_id=d.scan_id AND s.status='complete')) rows WHERE ` + predicate
}

func (p *Provider) ListScans(ctx context.Context) ([]Scan, error) {
	query := `
SELECT s.scan_id, s.scan_id, COALESCE(s.snablr_version,''), COALESCE(s.semantics,''), s.status,
       s.started_at, COALESCE(s.ended_at,''),
		` + p.listScanFindingCount() + `,
       COALESCE((SELECT group_concat(t.host, ', ') FROM targets t WHERE t.scan_id=s.scan_id), '')
FROM scans s ORDER BY s.started_at DESC`
	if p.hasDisplayIDs {
		query = `
SELECT s.scan_id, COALESCE(l.display_id,s.scan_id), COALESCE(s.snablr_version,''), COALESCE(s.semantics,''), s.status,
       s.started_at, COALESCE(s.ended_at,''),
       ` + p.listScanFindingCount() + `,
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

func (p *Provider) listScanFindingCount() string {
	if !p.hasDerivedFindings {
		return `(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.scan_id)`
	}
	return `(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.scan_id)+(SELECT COUNT(*) FROM derived_findings d WHERE d.scan_id=s.scan_id AND EXISTS (SELECT 1 FROM derived_state ds WHERE ds.scan_id=d.scan_id AND ds.status='complete'))`
}

func (p *Provider) Findings(ctx context.Context, scanID string, offset, limit int) ([]Finding, error) {
	if offset < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid findings page bounds")
	}
	query := p.findingRowsQuery("id,fingerprint,payload", "ORDER BY id LIMIT ? OFFSET ?")
	args := []any{scanID}
	if p.hasDerivedFindings {
		args = append(args, scanID)
	}
	args = append(args, limit, offset)
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read persisted findings: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (p *Provider) FindingsAfter(ctx context.Context, scanID string, afterID int64, limit int) ([]Finding, error) {
	if afterID < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid findings cursor bounds")
	}
	query := p.findingRowsQuery("id,fingerprint,payload", "WHERE id>? ORDER BY id LIMIT ?")
	args := []any{scanID}
	if p.hasDerivedFindings {
		args = append(args, scanID)
	}
	args = append(args, afterID, limit)
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read persisted findings after %d: %w", afterID, err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (p *Provider) Finding(ctx context.Context, scanID string, id int64) (Finding, error) {
	var item Finding
	var payload string
	var row *sql.Row
	if p.hasDerivedFindings && id >= derivedFindingIDBase {
		row = p.db.QueryRowContext(ctx, `SELECT `+fmt.Sprintf("%d", derivedFindingIDBase)+`+id,'derived:'||correlation_key,payload FROM derived_findings WHERE scan_id=? AND id=? AND EXISTS (SELECT 1 FROM derived_state WHERE scan_id=? AND status='complete')`, scanID, id-derivedFindingIDBase, scanID)
	} else {
		row = p.db.QueryRowContext(ctx, `SELECT id,fingerprint,payload FROM findings WHERE scan_id=? AND id=?`, scanID, id)
	}
	if err := row.Scan(&item.ID, &item.Fingerprint, &payload); err != nil {
		return Finding{}, fmt.Errorf("read persisted finding %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(payload), &item.Finding); err != nil {
		return Finding{}, fmt.Errorf("decode persisted finding %d: %w", id, err)
	}
	item.Derived = item.ID >= derivedFindingIDBase
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
	return scanCredentials(rows)
}

func (p *Provider) CredentialsAfter(ctx context.Context, scanID string, afterID int64, limit int) ([]Credential, error) {
	if afterID < 0 || limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid credentials cursor bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? AND id>? ORDER BY id LIMIT ?`, scanID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("read persisted credentials after %d: %w", afterID, err)
	}
	defer rows.Close()
	return scanCredentials(rows)
}

func (p *Provider) CredentialByID(ctx context.Context, scanID string, id int64) (Credential, error) {
	var item Credential
	var payload string
	if err := p.db.QueryRowContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? AND id=?`, scanID, id).Scan(&item.ID, &item.CredentialKey, &payload); err != nil {
		return Credential{}, fmt.Errorf("read persisted credential %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(payload), &item.Candidate); err != nil {
		return Credential{}, fmt.Errorf("decode persisted credential %d: %w", id, err)
	}
	return item, nil
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

// RelatedCredentials returns the bounded persisted group for one credential's
// logical identity. The caller owns projection and chooses the canonical row;
// this method only expands relationship context from indexed columns.
func (p *Provider) RelatedCredentials(ctx context.Context, scanID string, item Credential, limit int) ([]Credential, error) {
	return p.RelatedCredentialsAfter(ctx, scanID, item, 0, limit)
}

func (p *Provider) RelatedCredentialsAfter(ctx context.Context, scanID string, item Credential, afterID int64, limit int) ([]Credential, error) {
	if limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid credential relationship bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? AND credential_type=? AND identity=? AND value=? AND id>? ORDER BY id LIMIT ?`, scanID, item.Candidate.CredentialType, item.Candidate.Identity, item.Candidate.Value, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("read related credentials: %w", err)
	}
	defer rows.Close()
	result, err := scanCredentials(rows)
	if err != nil {
		return nil, err
	}
	return result, nil
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

func (p *Provider) CorrelationsAfter(ctx context.Context, scanID, afterKey string, limit int) ([]Correlation, error) {
	if limit <= 0 || limit > PageSize {
		return nil, fmt.Errorf("invalid correlations cursor bounds")
	}
	rows, err := p.db.QueryContext(ctx, `SELECT correlation_key,payload FROM correlations WHERE scan_id=? AND correlation_key>? ORDER BY correlation_key LIMIT ?`, scanID, afterKey, limit)
	if err != nil {
		return nil, fmt.Errorf("read persisted correlations after %q: %w", afterKey, err)
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
		return nil, fmt.Errorf("iterate persisted correlation rows: %w", err)
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
	page, err := p.SearchPage(ctx, scanID, query, PageSize)
	if err != nil {
		return nil, err
	}
	refs := make(map[string]struct{}, page.PersistedRows)
	for _, item := range page.Findings {
		refs[findingRowRef(item)] = struct{}{}
	}
	for _, item := range page.Credentials {
		refs[credentialRowRef(item)] = struct{}{}
	}
	for _, item := range page.Correlations {
		refs[correlationRowRef(item)] = struct{}{}
	}
	return refs, nil
}

// SearchPage returns only one bounded page of persisted search matches. The
// database performs the text filtering; evidence remains rehydratable by the
// stable row references in the returned projection.
func (p *Provider) SearchPage(ctx context.Context, scanID, query string, limit int) (SearchPage, error) {
	return p.SearchPageAfter(ctx, scanID, query, 0, 0, "", limit)
}

// SearchPageAfter returns the next bounded page of persisted search matches.
// Each population has an independent keyset cursor, so continuing a search
// never requires retaining previous pages or using OFFSET scans.
func (p *Provider) SearchPageAfter(ctx context.Context, scanID, query string, findingAfter, credentialAfter int64, correlationAfter string, limit int) (SearchPage, error) {
	if limit <= 0 || limit > PageSize {
		return SearchPage{}, fmt.Errorf("invalid search page bounds")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return SearchPage{}, nil
	}
	pattern := "%" + query + "%"
	result := SearchPage{}
	searchPredicate := `WHERE id>? AND (payload LIKE ? COLLATE NOCASE OR path LIKE ? COLLATE NOCASE OR rule_id LIKE ? COLLATE NOCASE) ORDER BY id LIMIT ?`
	searchQuery := p.findingRowsQuery("id,fingerprint,payload", searchPredicate)
	searchArgs := []any{scanID}
	if p.hasDerivedFindings {
		searchArgs = append(searchArgs, scanID)
	}
	searchArgs = append(searchArgs, findingAfter, pattern, pattern, pattern, limit)
	rows, err := p.db.QueryContext(ctx, searchQuery, searchArgs...)
	if err != nil {
		return SearchPage{}, fmt.Errorf("search persisted findings: %w", err)
	}
	result.Findings, err = scanFindings(rows)
	if err != nil {
		return SearchPage{}, err
	}
	rows, err = p.db.QueryContext(ctx, `SELECT id,credential_key,payload FROM credentials WHERE scan_id=? AND id>? AND (payload LIKE ? COLLATE NOCASE OR credential_key LIKE ? COLLATE NOCASE OR identity LIKE ? COLLATE NOCASE OR value LIKE ? COLLATE NOCASE) ORDER BY id LIMIT ?`, scanID, credentialAfter, pattern, pattern, pattern, pattern, limit)
	if err != nil {
		return SearchPage{}, fmt.Errorf("search persisted credentials: %w", err)
	}
	result.Credentials, err = scanCredentials(rows)
	if err != nil {
		return SearchPage{}, err
	}
	rows, err = p.db.QueryContext(ctx, `SELECT correlation_key,payload FROM correlations WHERE scan_id=? AND correlation_key>? AND payload LIKE ? COLLATE NOCASE ORDER BY correlation_key LIMIT ?`, scanID, correlationAfter, pattern, limit)
	if err != nil {
		return SearchPage{}, fmt.Errorf("search persisted correlations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item Correlation
		if err := rows.Scan(&item.Key, &item.Payload); err != nil {
			return SearchPage{}, fmt.Errorf("read persisted search correlation: %w", err)
		}
		result.Correlations = append(result.Correlations, item)
	}
	if err := rows.Err(); err != nil {
		return SearchPage{}, fmt.Errorf("iterate persisted search correlations: %w", err)
	}
	result.PersistedRows = len(result.Findings) + len(result.Credentials) + len(result.Correlations)
	if len(result.Findings) > 0 {
		result.FindingCursor = result.Findings[len(result.Findings)-1].ID
	}
	if len(result.Credentials) > 0 {
		result.CredentialCursor = result.Credentials[len(result.Credentials)-1].ID
	}
	if len(result.Correlations) > 0 {
		result.CorrelationCursor = result.Correlations[len(result.Correlations)-1].Key
	}
	result.Done = len(result.Findings) < limit && len(result.Credentials) < limit && len(result.Correlations) < limit
	return result, nil
}

func parseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func scanFindings(rows *sql.Rows) ([]Finding, error) {
	result := make([]Finding, 0, PageSize)
	for rows.Next() {
		var item Finding
		var payload string
		if err := rows.Scan(&item.ID, &item.Fingerprint, &payload); err != nil {
			return nil, fmt.Errorf("read persisted finding row: %w", err)
		}
		item.Derived = item.ID >= derivedFindingIDBase
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

func scanCredentials(rows *sql.Rows) ([]Credential, error) {
	result := make([]Credential, 0, PageSize)
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

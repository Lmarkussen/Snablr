package output

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/scanner"
)

// HTMLReportIndex is a temporary, disk-backed view of the HTML grouping and
// attached-report comparison contracts.
type HTMLReportIndex struct {
	db          *sql.DB
	path        string
	diffEnabled bool
}

type HTMLReportGroup struct {
	Key            string
	Category       string
	Primary        bool
	FindingCount   int
	DuplicateCount int
	CanonicalSeq   int64
}

type HTMLReportCategorySummary struct {
	Category        string
	Findings        int
	Critical        int
	High            int
	Medium          int
	Low             int
	HighestSeverity string
}

// BuildHTMLReportIndex consumes the bounded report iterator and writes only
// indexed grouping metadata plus JSON payloads to a temporary SQLite file.
// Finding payloads never accumulate in Go collections during preparation.
func BuildHTMLReportIndex(ctx context.Context, iterator HTMLReportFindingIterator) (*HTMLReportIndex, error) {
	if iterator == nil {
		return nil, errors.New("HTML report iterator is nil")
	}
	dir, err := os.MkdirTemp("", "snablr-html-index-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "report-index.sqlite")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	index := &HTMLReportIndex{db: db, path: path}
	if err := index.initialize(); err != nil {
		_ = index.Close()
		return nil, err
	}
	if err := index.ingest(ctx, iterator); err != nil {
		_ = index.Close()
		return nil, err
	}
	if err := index.materializeCanonical(ctx); err != nil {
		_ = index.Close()
		return nil, err
	}
	return index, nil
}

func (i *HTMLReportIndex) initialize() error {
	_, err := i.db.Exec(`
CREATE TABLE observations (
  seq INTEGER PRIMARY KEY,
  group_key TEXT NOT NULL,
  category TEXT NOT NULL,
  actionable INTEGER NOT NULL,
  correlated INTEGER NOT NULL,
  confidence REAL NOT NULL,
  severity_rank INTEGER NOT NULL,
  context_len INTEGER NOT NULL,
  path_preference INTEGER NOT NULL,
  unc_path TEXT NOT NULL,
  host TEXT NOT NULL,
  share TEXT NOT NULL,
  file_path TEXT NOT NULL,
	source TEXT NOT NULL,
	signal TEXT NOT NULL,
	from_sysvol INTEGER NOT NULL,
	from_netlogon INTEGER NOT NULL,
  location_key TEXT NOT NULL,
  anchor TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  credential_related INTEGER NOT NULL,
  payload BLOB NOT NULL
);
CREATE INDEX observations_group_order_idx ON observations(group_key, actionable DESC, correlated DESC, confidence DESC, severity_rank DESC, context_len DESC, path_preference DESC, length(unc_path), seq);
CREATE INDEX observations_group_location_idx ON observations(group_key, unc_path, seq);
CREATE INDEX observations_anchor_idx ON observations(anchor);
CREATE INDEX observations_fingerprint_idx ON observations(fingerprint, seq);
CREATE INDEX observations_credential_path_idx ON observations(credential_related, host, share, file_path, seq);
CREATE TABLE canonical (
  seq INTEGER PRIMARY KEY,
  group_key TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  actionable INTEGER NOT NULL,
  severity_rank INTEGER NOT NULL,
  host TEXT NOT NULL,
  share TEXT NOT NULL,
  file_path TEXT NOT NULL
);
CREATE INDEX canonical_category_idx ON canonical(actionable, severity_rank DESC, category, host, share, file_path);
`)
	return err
}

func (i *HTMLReportIndex) ingest(ctx context.Context, iterator reportFindingIterator) error {
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO observations(seq,group_key,category,actionable,correlated,confidence,severity_rank,context_len,path_preference,unc_path,host,share,file_path,source,signal,from_sysvol,from_netlogon,location_key,anchor,fingerprint,credential_related,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	seq := int64(0)
	err = iterator(ctx, func(finding scanner.Finding) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		payload, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		seq++
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			category = "uncategorized"
		}
		_, err = stmt.ExecContext(ctx, seq, reportDuplicateGroupKey(finding), category,
			boolInt(finding.Actionable), boolInt(finding.Correlated), finding.ConfidenceScore,
			severityRank(finding.Severity), len(strings.TrimSpace(finding.Context)), reportPathPreference(finding),
			uncPath(finding), finding.Host, finding.Share, finding.FilePath, normalizedSourceLabel(finding.Source), primarySignal(finding), boolInt(finding.FromSYSVOL), boolInt(finding.FromNETLOGON), reportLocationKey(finding), findingAnchor(finding), diffFingerprintKey(finding), boolInt(isCredentialRelatedFinding(finding)),
			payload)
		return err
	})
	_ = stmt.Close()
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (i *HTMLReportIndex) materializeCanonical(ctx context.Context) error {
	_, err := i.db.ExecContext(ctx, `
INSERT INTO canonical(seq,group_key,category,actionable,severity_rank,host,share,file_path)
SELECT seq,group_key,category,actionable,severity_rank,host,share,file_path
FROM (
  SELECT o.*, row_number() OVER (
    PARTITION BY group_key
    ORDER BY actionable DESC, correlated DESC, confidence DESC, severity_rank DESC,
      context_len DESC, path_preference DESC, length(unc_path) ASC, seq ASC
  ) AS position
  FROM observations o
)
WHERE position=1`)
	return err
}

// Close releases the temporary database and removes its private directory.
func (i *HTMLReportIndex) Close() error {
	if i == nil {
		return nil
	}
	var closeErr error
	if i.db != nil {
		closeErr = i.db.Close()
	}
	if i.path != "" {
		removeErr := os.RemoveAll(filepath.Dir(i.path))
		if closeErr == nil {
			closeErr = removeErr
		}
	}
	return closeErr
}

// DiskPath is intended for tests and measurements; callers must not modify it.
func (i *HTMLReportIndex) DiskPath() string {
	if i == nil {
		return ""
	}
	return i.path
}

func (i *HTMLReportIndex) CategorySummaries(ctx context.Context, primary bool) ([]HTMLReportCategorySummary, error) {
	if i == nil || i.db == nil {
		return nil, errors.New("HTML report index is closed")
	}
	rows, err := i.db.QueryContext(ctx, `SELECT category,COUNT(*),SUM(CASE WHEN severity_rank=4 THEN 1 ELSE 0 END),SUM(CASE WHEN severity_rank=3 THEN 1 ELSE 0 END),SUM(CASE WHEN severity_rank=2 THEN 1 ELSE 0 END),SUM(CASE WHEN severity_rank=1 THEN 1 ELSE 0 END),MAX(severity_rank) FROM canonical WHERE actionable=? GROUP BY category ORDER BY MAX(severity_rank) DESC,COUNT(*) DESC,category`, boolInt(primary))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HTMLReportCategorySummary
	for rows.Next() {
		var summary HTMLReportCategorySummary
		var highest int
		if err := rows.Scan(&summary.Category, &summary.Findings, &summary.Critical, &summary.High, &summary.Medium, &summary.Low, &highest); err != nil {
			return nil, err
		}
		summary.HighestSeverity = severityName(highest)
		out = append(out, summary)
	}
	return out, rows.Err()
}

func severityName(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "unknown"
	}
}

// ForEachGroup iterates canonical groups in the same ordering used by the
// existing HTML grouping path. It never materializes group members.
func (i *HTMLReportIndex) ForEachGroup(ctx context.Context, primary bool, visit func(HTMLReportGroup) error) error {
	if i == nil || i.db == nil {
		return errors.New("HTML report index is closed")
	}
	if visit == nil {
		return errors.New("HTML report group visitor is nil")
	}
	rows, err := i.db.QueryContext(ctx, `WITH category_order AS (SELECT category,MAX(severity_rank) AS category_severity,COUNT(*) AS category_count FROM canonical WHERE actionable=? GROUP BY category) SELECT c.group_key,c.category,c.actionable,c.seq,COUNT(DISTINCT o.location_key)-1 FROM canonical c JOIN observations o ON o.group_key=c.group_key JOIN category_order co ON co.category=c.category WHERE c.actionable=? GROUP BY c.seq,c.group_key,c.category,c.actionable ORDER BY co.category_severity DESC,co.category_count DESC,c.category,c.severity_rank DESC,c.host,c.share,c.file_path`, boolInt(primary), boolInt(primary))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var group HTMLReportGroup
		if err := rows.Scan(&group.Key, &group.Category, &group.Primary, &group.CanonicalSeq, &group.DuplicateCount); err != nil {
			return err
		}
		group.FindingCount = group.DuplicateCount + 1
		if err := visit(group); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (i *HTMLReportIndex) GroupMetadata(ctx context.Context, groupKey string) (string, string, error) {
	var payload, paths, scopes []byte
	err := i.db.QueryRowContext(ctx, `SELECT o.payload,COALESCE((SELECT group_concat(unc_path,' ') FROM observations WHERE group_key=?),''),COALESCE((SELECT group_concat(host || ' ' || share,' ') FROM observations WHERE group_key=?),'') FROM canonical c JOIN observations o ON o.seq=c.seq WHERE c.group_key=?`, groupKey, groupKey, groupKey).Scan(&payload, &paths, &scopes)
	if err != nil {
		return "", "", err
	}
	var finding scanner.Finding
	if err := json.Unmarshal(payload, &finding); err != nil {
		return "", "", err
	}
	search := strings.TrimSpace(findingSearchText(finding, nil, "") + " " + string(paths))
	return search, strings.TrimSpace(string(scopes)), nil
}

func (i *HTMLReportIndex) GroupCount(ctx context.Context, primary bool) (int, error) {
	var count int
	err := i.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM canonical WHERE actionable=?`, boolInt(primary)).Scan(&count)
	return count, err
}

func (i *HTMLReportIndex) FilterOptions(ctx context.Context) (reportFilterOptions, error) {
	var options reportFilterOptions
	queries := []struct {
		dest  *[]string
		query string
	}{
		{&options.Categories, `SELECT DISTINCT category FROM canonical ORDER BY category`},
		{&options.Sources, `SELECT DISTINCT source FROM observations o JOIN canonical c ON c.seq=o.seq WHERE source<>'' ORDER BY source`},
		{&options.Signals, `SELECT DISTINCT signal FROM observations o JOIN canonical c ON c.seq=o.seq WHERE signal<>'' ORDER BY signal`},
	}
	for _, item := range queries {
		rows, err := i.db.QueryContext(ctx, item.query)
		if err != nil {
			return options, err
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				_ = rows.Close()
				return options, err
			}
			*item.dest = append(*item.dest, value)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return options, err
		}
		if err := rows.Close(); err != nil {
			return options, err
		}
	}
	rows, err := i.db.QueryContext(ctx, `SELECT DISTINCT o.host || ' ' || o.share FROM observations o JOIN canonical c ON c.seq=o.seq WHERE o.host<>'' OR o.share<>'' ORDER BY o.host,o.share`)
	if err != nil {
		return options, err
	}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return options, err
		}
		options.Scopes = append(options.Scopes, value)
	}
	return options, rows.Err()
}

func (i *HTMLReportIndex) HostSummaries(ctx context.Context) ([]hostSummary, error) {
	rows, err := i.db.QueryContext(ctx, `SELECT CASE WHEN o.host='' THEN 'unknown-host' ELSE o.host END,COUNT(*),COUNT(DISTINCT o.share),COUNT(DISTINCT o.category),MAX(o.severity_rank),MAX(o.source='ldap'),MAX(o.source='dfs'),MAX(o.from_sysvol),MAX(o.from_netlogon) FROM observations o JOIN canonical c ON c.seq=o.seq GROUP BY CASE WHEN o.host='' THEN 'unknown-host' ELSE o.host END ORDER BY MAX(o.severity_rank) DESC,COUNT(*) DESC,CASE WHEN o.host='' THEN 'unknown-host' ELSE o.host END LIMIT 12`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hostSummary
	for rows.Next() {
		var item hostSummary
		var severity, ldap, dfs, sysvol, netlogon int
		if err := rows.Scan(&item.Host, &item.Findings, &item.Shares, &item.Categories, &severity, &ldap, &dfs, &sysvol, &netlogon); err != nil {
			return nil, err
		}
		item.HighestSeverity = severityName(severity)
		item.FromLDAP, item.FromDFS = ldap != 0, dfs != 0
		item.FromSYSVOL, item.FromNETLOGON = sysvol != 0, netlogon != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func (i *HTMLReportIndex) TopAccessPaths(ctx context.Context, limit int) ([]accessPathSummary, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := i.db.QueryContext(ctx, `SELECT o.payload FROM observations o JOIN canonical c ON c.seq=o.seq WHERE o.correlated=1 ORDER BY o.severity_rank DESC,o.seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]accessPathSummary, 0, limit)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, err
		}
		item, ok := classifyAccessPath(finding)
		if !ok {
			continue
		}
		items = append(items, item)
		for a := len(items) - 1; a > 0 && accessPathLess(items[a], items[a-1]); a-- {
			items[a], items[a-1] = items[a-1], items[a]
		}
		if len(items) > limit {
			items = items[:limit]
		}
	}
	for n := range items {
		items[n].Rank = n + 1
	}
	return items, rows.Err()
}

func accessPathLess(left, right accessPathSummary) bool {
	if left.ExploitabilityScore != right.ExploitabilityScore {
		return left.ExploitabilityScore > right.ExploitabilityScore
	}
	if severityRank(left.Severity) != severityRank(right.Severity) {
		return severityRank(left.Severity) > severityRank(right.Severity)
	}
	if len(left.RelatedArtifacts) != len(right.RelatedArtifacts) {
		return len(left.RelatedArtifacts) > len(right.RelatedArtifacts)
	}
	if left.Host != right.Host {
		return left.Host < right.Host
	}
	if left.Share != right.Share {
		return left.Share < right.Share
	}
	if left.PrimaryPath != right.PrimaryPath {
		return left.PrimaryPath < right.PrimaryPath
	}
	return left.RuleID < right.RuleID
}

// Canonical returns one decoded representative and releases it when the
// caller returns. Related observations remain on disk.
func (i *HTMLReportIndex) Canonical(ctx context.Context, groupKey string) (scanner.Finding, error) {
	var payload []byte
	err := i.db.QueryRowContext(ctx, `SELECT o.payload FROM canonical c JOIN observations o ON o.seq=c.seq WHERE c.group_key=?`, groupKey).Scan(&payload)
	if err != nil {
		return scanner.Finding{}, err
	}
	var finding scanner.Finding
	if err := json.Unmarshal(payload, &finding); err != nil {
		return scanner.Finding{}, fmt.Errorf("decode canonical HTML finding: %w", err)
	}
	return finding, nil
}

// ForEachDuplicate streams unique noncanonical locations sorted by UNC path.
func (i *HTMLReportIndex) ForEachDuplicate(ctx context.Context, groupKey string, visit func(scanner.Finding) error) error {
	if visit == nil {
		return errors.New("HTML duplicate visitor is nil")
	}
	rows, err := i.db.QueryContext(ctx, `SELECT o.payload FROM observations o JOIN canonical c ON c.group_key=o.group_key WHERE o.group_key=? AND o.seq<>c.seq GROUP BY o.location_key ORDER BY o.unc_path,o.seq`, groupKey)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return err
		}
		if err := visit(finding); err != nil {
			return err
		}
	}
	return rows.Err()
}

// CredentialAnchor resolves the stable HTML anchor to its persisted group.
func (i *HTMLReportIndex) CredentialAnchor(ctx context.Context, anchor string) (string, bool, error) {
	var group string
	err := i.db.QueryRowContext(ctx, `SELECT c.group_key FROM observations o JOIN canonical c ON c.seq=o.seq WHERE o.anchor=? LIMIT 1`, anchor).Scan(&group)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return group, err == nil, err
}

// CredentialAnchorForProvenance resolves a candidate's concrete source path to
// the canonical credential-related card without building a Go-side card map.
func (i *HTMLReportIndex) CredentialAnchorForProvenance(ctx context.Context, host, share, path string) (string, bool, error) {
	var anchor string
	err := i.db.QueryRowContext(ctx, `
SELECT canonical_observation.anchor
FROM observations candidate
JOIN canonical canonical_group ON canonical_group.group_key=candidate.group_key
JOIN observations canonical_observation ON canonical_observation.seq=canonical_group.seq
WHERE candidate.credential_related=1 AND lower(trim(candidate.host))=lower(trim(?))
  AND lower(trim(candidate.share))=lower(trim(?))
  AND replace(lower(trim(candidate.file_path)),'\\','/')=replace(lower(trim(?)),'\\','/')
ORDER BY candidate.seq LIMIT 1`, host, share, path).Scan(&anchor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return anchor, err == nil, err
}

package store

import (
	"context"
	"fmt"
	"strings"
)

type SearchResultType string

const (
	SearchResultFile       SearchResultType = "FILE"
	SearchResultFinding    SearchResultType = "FINDING"
	SearchResultCredential SearchResultType = "CREDENTIAL"
	SearchResultEvidence   SearchResultType = "EVIDENCE"
)

type SearchResult struct {
	Type    SearchResultType
	ID      string
	Title   string
	Context string
	Detail  string
}

type SearchOptions struct {
	Limit  int
	Offset int
}

func (s *SQLiteStore) Search(ctx context.Context, query string, options SearchOptions) ([]SearchResult, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("sqlite search store is closed")
	}
	query = escapeLike(strings.TrimSpace(query))
	if query == "" {
		return nil, nil
	}
	if options.Limit <= 0 || options.Limit > 100 {
		options.Limit = 100
	}
	if options.Offset < 0 {
		options.Offset = 0
	}

	// The LIKE predicates are intentionally bounded and run on the database
	// connection. Search never materializes the scan inventory in Go memory.
	const searchSQL = `
SELECT result_type, result_id, title, context, detail FROM (
  SELECT 'FILE' AS result_type, file_key AS result_id, path AS title, host || ' / ' || share AS context, path || '  [' || host || ' / ' || share || ']' AS detail
    FROM files
   WHERE scan_id=? AND (path LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR host LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR share LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\')
  UNION ALL
  SELECT 'FINDING' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(rule_id, category, 'finding') AS title, host || ' / ' || share AS context, path AS detail
    FROM findings
   WHERE scan_id=? AND (rule_id LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR category LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR host LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR share LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR path LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\')
  UNION ALL
  SELECT 'EVIDENCE' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(rule_id, 'evidence') AS title, path AS context, substr(payload, 1, 240) AS detail
    FROM findings
   WHERE scan_id=? AND payload LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND rule_id NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND category NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND host NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND share NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND path NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
  UNION ALL
  SELECT 'CREDENTIAL' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(identity, credential_type, 'credential') AS title, credential_type AS context, identity || ' = ' || value AS detail
    FROM credentials
   WHERE scan_id=? AND (identity LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR value LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR credential_type LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR payload LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\')
)
ORDER BY result_type, result_id
LIMIT ? OFFSET ?`

	args := []any{
		s.scanID, query, query, query,
		s.scanID, query, query, query, query, query,
		s.scanID, query, query, query, query, query, query,
		s.scanID, query, query, query, query,
		options.Limit, options.Offset,
	}
	rows, err := s.db.QueryContext(ctx, searchSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]SearchResult, 0, options.Limit)
	for rows.Next() {
		var result SearchResult
		if err := rows.Scan(&result.Type, &result.ID, &result.Title, &result.Context, &result.Detail); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

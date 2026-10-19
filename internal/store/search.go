package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"snablr/internal/credentialanalysis"
)

type SearchResultType string

const (
	SearchResultFile       SearchResultType = "FILE"
	SearchResultFinding    SearchResultType = "FINDING"
	SearchResultCredential SearchResultType = "CREDENTIAL"
	SearchResultEvidence   SearchResultType = "EVIDENCE"
)

type SearchResult struct {
	Type        SearchResultType
	ID          string
	Title       string
	Context     string
	Detail      string
	Source      string
	BookmarkKey string
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
	SELECT result_type, result_id, title, context, detail, source, bookmark_key, credential_payload, credential_type, credential_identity, credential_value FROM (
	  SELECT 'FILE' AS result_type, file_key AS result_id, path AS title, host || ' / ' || share AS context, path || '  [' || host || ' / ' || share || ']' AS detail, path AS source, file_key AS bookmark_key, '' AS credential_payload, '' AS credential_type, '' AS credential_identity, '' AS credential_value
    FROM files
   WHERE scan_id=? AND (path LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR host LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR share LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\')
  UNION ALL
	  SELECT 'FINDING' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(rule_id, category, 'finding') AS title, host || ' / ' || share AS context, path AS detail, path AS source, COALESCE((SELECT file_key FROM files f WHERE f.scan_id=findings.scan_id AND f.host=findings.host AND f.share=findings.share AND (f.path=findings.path OR findings.path LIKE f.path || '!%') LIMIT 1), '') AS bookmark_key, '' AS credential_payload, '' AS credential_type, '' AS credential_identity, '' AS credential_value
    FROM findings
   WHERE scan_id=? AND (rule_id LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR category LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR host LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR share LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\' OR path LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\')
  UNION ALL
	  SELECT 'EVIDENCE' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(rule_id, 'evidence') AS title, path AS context, substr(payload, 1, 240) AS detail, path AS source, COALESCE((SELECT file_key FROM files f WHERE f.scan_id=findings.scan_id AND f.host=findings.host AND f.share=findings.share AND (f.path=findings.path OR findings.path LIKE f.path || '!%') LIMIT 1), '') AS bookmark_key, '' AS credential_payload, '' AS credential_type, '' AS credential_identity, '' AS credential_value
    FROM findings
   WHERE scan_id=? AND payload LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND rule_id NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND category NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND host NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND share NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
     AND path NOT LIKE '%' || ? || '%' COLLATE NOCASE ESCAPE '\'
  UNION ALL
	  SELECT 'CREDENTIAL' AS result_type, CAST(id AS TEXT) AS result_id, COALESCE(identity, credential_type, 'credential') AS title, credential_type AS context, COALESCE(identity, credential_type, 'credential') || ' | ' || COALESCE(value, '') AS detail, credential_key AS source, COALESCE((SELECT file_key FROM files f WHERE f.scan_id=credentials.scan_id AND instr(credentials.credential_key, '|' || f.path || '|') > 0 LIMIT 1), '') AS bookmark_key, payload AS credential_payload, credential_type, identity, value
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
	}
	results := make([]SearchResult, 0, options.Limit)
	logicalOffset := 0
	rawOffset := 0
	batchSize := options.Limit
	if batchSize < 100 {
		batchSize = 100
	}
	for {
		batchArgs := append(append([]any{}, args...), batchSize, rawOffset)
		rows, err := s.db.QueryContext(ctx, searchSQL, batchArgs...)
		if err != nil {
			return nil, err
		}
		rowCount := 0
		for rows.Next() {
			rowCount++
			var result SearchResult
			var credentialPayload string
			var credentialType, credentialIdentity, credentialValue string
			if err := rows.Scan(&result.Type, &result.ID, &result.Title, &result.Context, &result.Detail, &result.Source, &result.BookmarkKey, &credentialPayload, &credentialType, &credentialIdentity, &credentialValue); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if result.Type == SearchResultCredential && suppressedCredentialPayload(credentialPayload, credentialType, credentialIdentity, credentialValue) {
				continue
			}
			if logicalOffset < options.Offset {
				logicalOffset++
				continue
			}
			results = append(results, result)
			if len(results) >= options.Limit {
				break
			}
		}
		rowErr := rows.Err()
		_ = rows.Close()
		if rowErr != nil {
			return nil, rowErr
		}
		if len(results) >= options.Limit || rowCount < batchSize {
			break
		}
		rawOffset += rowCount
	}
	return results, nil
}

func suppressedCredentialPayload(payload, credentialType, identity, value string) bool {
	if strings.TrimSpace(payload) == "" {
		return false
	}
	var candidate credentialanalysis.Candidate
	if err := json.Unmarshal([]byte(payload), &candidate); err != nil {
		return false
	}
	candidate.CredentialType = credentialType
	candidate.Identity = identity
	candidate.Value = value
	_, suppressed := credentialanalysis.SuppressionReason(candidate)
	return suppressed
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

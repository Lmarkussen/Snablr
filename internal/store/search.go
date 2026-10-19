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
	type credentialSearchCandidate struct {
		candidate   credentialanalysis.Candidate
		resultIndex int
	}
	seenCredentials := make([]credentialSearchCandidate, 0)
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
			if result.Type == SearchResultCredential {
				candidate, suppressed, decoded := persistedCandidate(credentialPayload, credentialType, credentialIdentity, credentialValue)
				if suppressed {
					continue
				}
				if decoded {
					duplicate := false
					for index := range seenCredentials {
						if !credentialanalysis.SameLogicalCredential(seenCredentials[index].candidate, candidate) {
							continue
						}
						duplicate = true
						if preferCredentialCandidate(candidate, seenCredentials[index].candidate) {
							seenCredentials[index].candidate = candidate
							results[seenCredentials[index].resultIndex] = credentialSearchResult(result, candidate)
						}
						break
					}
					if duplicate {
						continue
					}
				}
				if logicalOffset < options.Offset {
					logicalOffset++
					continue
				}
				resultIndex := len(results)
				results = append(results, credentialSearchResult(result, candidate))
				if decoded {
					seenCredentials = append(seenCredentials, credentialSearchCandidate{candidate: candidate, resultIndex: resultIndex})
				}
				if len(results) >= options.Limit {
					break
				}
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

func persistedCandidate(payload, credentialType, identity, value string) (credentialanalysis.Candidate, bool, bool) {
	var candidate credentialanalysis.Candidate
	if strings.TrimSpace(payload) == "" {
		return candidate, false, false
	}
	if err := json.Unmarshal([]byte(payload), &candidate); err != nil {
		return candidate, false, false
	}
	candidate.CredentialType = credentialType
	candidate.Identity = identity
	candidate.Value = value
	_, suppressed := credentialanalysis.SuppressionReason(candidate)
	return candidate, suppressed, true
}

func preferCredentialCandidate(candidate, existing credentialanalysis.Candidate) bool {
	if strings.TrimSpace(candidate.Identity) != "" && strings.TrimSpace(existing.Identity) == "" {
		return true
	}
	if candidate.Verification == credentialanalysis.Confirmed && existing.Verification != credentialanalysis.Confirmed {
		return true
	}
	return len(candidate.Evidence) > len(existing.Evidence)
}

func credentialSearchResult(result SearchResult, candidate credentialanalysis.Candidate) SearchResult {
	result.Title = firstSearchString(candidate.Identity, candidate.CredentialType, "credential")
	result.Context = candidate.CredentialType
	result.Detail = result.Title + " | " + candidate.Value
	return result
}

func firstSearchString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

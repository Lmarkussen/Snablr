package findings

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// GlobalSearchResult is one persisted record and the field that matched. The
// payload is kept intact so the search window can show the original evidence.
type GlobalSearchResult struct {
	Kind, ID, Field, Value, Context string
}

const globalSearchPageSize = 5

func (p *Provider) GlobalSearchPage(ctx context.Context, scanID, query string, phase, offset, limit int) ([]GlobalSearchResult, int, int, bool, error) {
	if limit < 1 || limit > globalSearchPageSize || phase < 0 || offset < 0 {
		return nil, 0, 0, false, fmt.Errorf("invalid global search page bounds")
	}
	if query == "" {
		return nil, 0, 0, true, nil
	}
	// Escape LIKE metacharacters so every query is a literal substring.
	pattern := query
	q := `
SELECT kind,id,field,value,context FROM (
 SELECT 'file' kind,file_key id,'path' field,path value,host||' / '||share context FROM files WHERE scan_id=? AND (path LIKE ? COLLATE NOCASE ESCAPE '\' OR host LIKE ? COLLATE NOCASE ESCAPE '\' OR share LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'finding',CAST(id AS TEXT),'finding details',payload,COALESCE(path,'') FROM findings WHERE scan_id=? AND (payload LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(path,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(rule_id,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(category,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(host,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(share,'') LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'credential',CAST(id AS TEXT),CASE WHEN COALESCE(identity,'') LIKE ? COLLATE NOCASE ESCAPE '\' THEN 'username' WHEN COALESCE(value,'') LIKE ? COLLATE NOCASE ESCAPE '\' THEN 'credential value' ELSE 'credential details' END, payload||char(10)||COALESCE(identity,'')||char(10)||COALESCE(value,'')||char(10)||COALESCE(credential_key,''),CASE WHEN json_valid(payload) THEN COALESCE(json_extract(payload,'$.Path'),'') ELSE '' END FROM credentials WHERE scan_id=? AND (payload LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(credential_key,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(credential_type,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(identity,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(value,'') LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'correlation',correlation_key,'correlation details',payload,correlation_key FROM correlations WHERE scan_id=? AND (correlation_key LIKE ? COLLATE NOCASE ESCAPE '\' OR payload LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'derived finding',correlation_key,'derived finding details',payload,COALESCE(json_extract(payload,'$.file_path'),'') FROM derived_findings WHERE scan_id=? AND (payload LIKE ? COLLATE NOCASE ESCAPE '\' OR correlation_key LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'member',member_key,'member path / provenance',member_path||' '||COALESCE(provenance,''),parent_key FROM members WHERE scan_id=? AND (member_path LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(provenance,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR member_key LIKE ? COLLATE NOCASE ESCAPE '\' OR parent_key LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'access observation',context_id,'access metadata',access_result,context_id FROM access_observations WHERE scan_id=? AND (context_id LIKE ? COLLATE NOCASE ESCAPE '\' OR access_result LIKE ? COLLATE NOCASE ESCAPE '\' OR file_key LIKE ? COLLATE NOCASE ESCAPE '\')

 UNION ALL SELECT 'share',host||'/'||share,'share name / host',host||' '||share,host FROM shares WHERE scan_id=? AND (host LIKE ? COLLATE NOCASE ESCAPE '\' OR share LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'target',host,'target metadata',status,host FROM targets WHERE scan_id=? AND (host LIKE ? COLLATE NOCASE ESCAPE '\' OR status LIKE ? COLLATE NOCASE ESCAPE '\')
 UNION ALL SELECT 'scan metadata',scan_id,'scan metadata',COALESCE(snablr_version,'')||' '||COALESCE(semantics,'')||' '||status,scan_id FROM scans WHERE scan_id=? AND (scan_id LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(snablr_version,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR COALESCE(semantics,'') LIKE ? COLLATE NOCASE ESCAPE '\' OR status LIKE ? COLLATE NOCASE ESCAPE '\')
) ORDER BY kind,id,field LIMIT ? OFFSET ?`
	if !p.hasDerivedFindings {
		q = strings.Replace(q, " UNION ALL SELECT 'derived finding',correlation_key,'derived finding details',payload,COALESCE(json_extract(payload,'$.file_path'),'') FROM derived_findings WHERE scan_id=? AND (payload LIKE ? COLLATE NOCASE ESCAPE '\\' OR correlation_key LIKE ? COLLATE NOCASE ESCAPE '\\')", "", 1)
	}
	q = regexp.MustCompile(`(?i)(COALESCE\([^)]*\)|[a-z_][a-z0-9_]*) LIKE \? COLLATE NOCASE ESCAPE '\\'`).ReplaceAllString(q, "snablr_contains($1,?)")
	a := []any{scanID, pattern, pattern, pattern, scanID, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, scanID, pattern, pattern, pattern, pattern, pattern, scanID, pattern, pattern}
	if p.hasDerivedFindings {
		a = append(a, scanID, pattern, pattern)
	}
	a = append(a, scanID, pattern, pattern, pattern, pattern, scanID, pattern, pattern, pattern, scanID, pattern, pattern, scanID, pattern, pattern, scanID, pattern, pattern, pattern, pattern, limit, offset)
	start := strings.Index(q, "\n SELECT ")
	end := strings.LastIndex(q, "\n) ORDER BY")
	if start < 0 || end < 0 {
		return nil, 0, 0, false, fmt.Errorf("invalid global search query")
	}
	parts := strings.Split(q[start+2:end], "\n UNION ALL ")
	counts := []int{4, 7, 8, 3}
	if p.hasDerivedFindings {
		counts = append(counts, 3)
	}
	counts = append(counts, 5, 4, 3, 3, 5)
	if len(parts) != len(counts) {
		return nil, 0, 0, false, fmt.Errorf("invalid global search populations")
	}
	type population struct {
		sql      string
		args     []any
		order    string
		priority int
	}
	orders := []string{"file_key", "id", "id", "correlation_key", "id", "parent_key,member_key", "context_id,file_key", "host,share", "host", "scan_id"}
	priorities := []int{2, 1, 0, 3, 4, 5, 6, 7, 8, 9}
	if !p.hasDerivedFindings {
		orders = append(orders[:4], orders[5:]...)
		priorities = append(priorities[:4], priorities[5:]...)
	}
	populations := make([]population, 0, len(parts))
	index := 0
	for i, part := range parts {
		populations = append(populations, population{sql: part, args: a[index : index+counts[i]], order: orders[i], priority: priorities[i]})
		index += counts[i]
	}
	sort.Slice(populations, func(i, j int) bool { return populations[i].priority < populations[j].priority })
	for phase < len(populations) {
		entry := populations[phase]
		args := append(append([]any(nil), entry.args...), limit, offset)
		rows, err := p.db.QueryContext(ctx, entry.sql+" ORDER BY "+entry.order+" LIMIT ? OFFSET ?", args...)
		if err != nil {
			return nil, 0, 0, false, fmt.Errorf("search persisted Finder data: %w", err)
		}
		out := make([]GlobalSearchResult, 0, limit)
		for rows.Next() {
			var x GlobalSearchResult
			if err := rows.Scan(&x.Kind, &x.ID, &x.Field, &x.Value, &x.Context); err != nil {
				_ = rows.Close()
				return nil, 0, 0, false, err
			}
			out = append(out, x)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return nil, 0, 0, false, err
		}
		if closeErr != nil {
			return nil, 0, 0, false, closeErr
		}
		if len(out) == limit {
			return out, phase, offset + len(out), false, nil
		}
		phase++
		offset = 0
		if len(out) > 0 {
			return out, phase, offset, phase == len(populations), nil
		}
	}
	return nil, phase, 0, true, nil
}

func (p *Provider) GlobalSearch(ctx context.Context, scanID, query string, limit, offset int) ([]GlobalSearchResult, error) {
	if limit < 1 || limit > globalSearchPageSize || offset < 0 {
		return nil, fmt.Errorf("invalid global search page bounds")
	}
	phase, phaseOffset, skipped := 0, 0, 0
	var out []GlobalSearchResult
	for {
		page, nextPhase, nextOffset, done, err := p.GlobalSearchPage(ctx, scanID, query, phase, phaseOffset, globalSearchPageSize)
		if err != nil {
			return nil, err
		}
		for _, row := range page {
			if skipped < offset {
				skipped++
				continue
			}
			out = append(out, row)
			if len(out) == limit {
				return out, nil
			}
		}
		if done {
			return out, nil
		}
		phase, phaseOffset = nextPhase, nextOffset
	}
}

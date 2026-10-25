package output

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/diff"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

type jsonSQLiteState struct {
	db       *sql.DB
	path     string
	rawCount int
}

func newJSONSQLiteState() (*jsonSQLiteState, error) {
	file, err := os.CreateTemp("", "snablr-json-state-*.db")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE report_findings (dedup_key TEXT PRIMARY KEY, severity INTEGER NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, file_path TEXT NOT NULL, rule_id TEXT NOT NULL, payload BLOB NOT NULL); CREATE TABLE report_fingerprints (fingerprint TEXT PRIMARY KEY, payload BLOB NOT NULL); CREATE TABLE access_paths (score INTEGER NOT NULL, severity INTEGER NOT NULL, related INTEGER NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, primary_path TEXT NOT NULL, rule_id TEXT NOT NULL, payload BLOB NOT NULL)`); err != nil {
		_ = db.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return &jsonSQLiteState{db: db, path: path}, nil
}

func (s *jsonSQLiteState) close() error {
	if s == nil {
		return nil
	}
	err := s.db.Close()
	if removeErr := os.Remove(s.path); err == nil {
		err = removeErr
	}
	return err
}

func (s *jsonSQLiteState) ingest(ctx context.Context, finding scanner.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.rawCount++
	key := reportFindingDedupKey(finding)
	payload, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	var existingPayload []byte
	err = s.db.QueryRowContext(ctx, `SELECT payload FROM report_findings WHERE dedup_key=?`, key).Scan(&existingPayload)
	if err == sql.ErrNoRows {
		if _, err = s.db.ExecContext(ctx, `INSERT INTO report_findings(dedup_key,severity,host,share,file_path,rule_id,payload) VALUES(?,?,?,?,?,?,?)`, key, severityRank(finding.Severity), finding.Host, finding.Share, finding.FilePath, finding.RuleID, payload); err != nil {
			return err
		}
		return s.recordFingerprint(ctx, finding, payload)
	}
	if err != nil {
		return err
	}
	var existing scanner.Finding
	if err := json.Unmarshal(existingPayload, &existing); err != nil {
		return err
	}
	preferred := betterReportFinding(existing, finding)
	if reportFindingDedupKey(preferred) == key {
		payload, err = json.Marshal(preferred)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, `UPDATE report_findings SET severity=?,host=?,share=?,file_path=?,rule_id=?,payload=? WHERE dedup_key=?`, severityRank(preferred.Severity), preferred.Host, preferred.Share, preferred.FilePath, preferred.RuleID, payload, key)
		if err != nil {
			return err
		}
		return s.recordFingerprint(ctx, preferred, payload)
	}
	return nil
}

func (s *jsonSQLiteState) recordFingerprint(ctx context.Context, finding scanner.Finding, payload []byte) error {
	fingerprint, err := json.Marshal(diff.Fingerprint(finding))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO report_fingerprints(fingerprint,payload) VALUES(?,?) ON CONFLICT(fingerprint) DO UPDATE SET payload=excluded.payload`, string(fingerprint), payload)
	return err
}

func (s *jsonSQLiteState) classificationDistribution(ctx context.Context) ([]diff.ClassificationSummary, error) {
	counts := make(map[string]int)
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM report_findings ORDER BY severity DESC,host,share,file_path,rule_id,dedup_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, err
		}
		class := strings.ToLower(strings.TrimSpace(finding.TriageClass))
		if class == "" {
			class = "unclassified"
		}
		counts[class]++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]diff.ClassificationSummary, 0, len(counts))
	for class, count := range counts {
		out = append(out, diff.ClassificationSummary{Class: class, Count: count})
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Count == out[k].Count {
			return out[i].Class < out[k].Class
		}
		return out[i].Count > out[k].Count
	})
	return out, nil
}

func (s *jsonSQLiteState) categorySummaries(ctx context.Context) ([]categorySummary, error) {
	counts := make(map[string]*categorySummary)
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM report_findings ORDER BY dedup_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, err
		}
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			category = "uncategorized"
		}
		summary := counts[category]
		if summary == nil {
			summary = &categorySummary{Category: category, RemediationGuidance: remediationGuidanceForCategory(category)}
			counts[category] = summary
		}
		summary.Findings++
		switch strings.ToLower(finding.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
		if severityRank(finding.Severity) > severityRank(summary.HighestSeverity) {
			summary.HighestSeverity = finding.Severity
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]categorySummary, 0, len(counts))
	for _, item := range counts {
		if strings.TrimSpace(item.HighestSeverity) == "" {
			item.HighestSeverity = "unknown"
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := severityRank(out[i].HighestSeverity), severityRank(out[j].HighestSeverity)
		if left == right {
			if out[i].Findings == out[j].Findings {
				return out[i].Category < out[j].Category
			}
			return out[i].Findings > out[j].Findings
		}
		return left > right
	})
	return out, nil
}

func (s *jsonSQLiteState) prepareAccessPaths(ctx context.Context) error {
	var after string
	for {
		var key string
		var payload []byte
		err := s.db.QueryRowContext(ctx, `SELECT dedup_key,payload FROM report_findings WHERE dedup_key>? ORDER BY dedup_key LIMIT 1`, after).Scan(&key, &payload)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		after = key
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return err
		}
		item, ok := classifyAccessPath(finding)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO access_paths(score,severity,related,host,share,primary_path,rule_id,payload) VALUES(?,?,?,?,?,?,?,?)`, item.ExploitabilityScore, severityRank(item.Severity), len(item.RelatedArtifacts), item.Host, item.Share, item.PrimaryPath, item.RuleID, encoded); err != nil {
			return err
		}
	}
}
func (s *jsonSQLiteState) writeAccessPaths(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM access_paths ORDER BY score DESC,severity DESC,related DESC,host,share,primary_path,rule_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	first := true
	rank := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var item accessPathSummary
		if err := json.Unmarshal(payload, &item); err != nil {
			return err
		}
		rank++
		item.Rank = rank
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := w.Write(encoded); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "]")
	return err
}

func (s *jsonSQLiteState) writeFindings(ctx context.Context, w io.Writer, pretty bool, status func(scanner.Finding) diff.FindingDelta) error {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM report_findings ORDER BY severity DESC,host,share,file_path,rule_id,dedup_key`)
	if err != nil {
		return err
	}
	defer rows.Close()
	first := true
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var finding scanner.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return err
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		delta := diff.FindingDelta{}
		if status != nil {
			delta = status(finding)
		}
		encoded, err := json.Marshal(toJSONFinding(finding, delta))
		if err != nil {
			return err
		}
		if pretty {
			if _, err := io.WriteString(w, "\n  "); err != nil {
				return err
			}
		}
		if _, err := w.Write(encoded); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "]")
	return err
}

func writeJSONMetadata(w io.Writer, values map[string]any) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	for index, key := range keys {
		if index > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		name, _ := json.Marshal(key)
		value, err := json.Marshal(values[key])
		if err != nil {
			return err
		}
		if _, err := w.Write(name); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ":"); err != nil {
			return err
		}
		if _, err := w.Write(value); err != nil {
			return err
		}
	}
	return nil
}

func closeJSONSQLiteStreaming(j *JSONWriter, shadow *store.SQLiteStore) error {
	return closeJSONSQLiteStreamingWithBaseline(j, shadow, nil)
}

func closeJSONSQLiteStreamingWithBaseline(j *JSONWriter, shadow *store.SQLiteStore, baseline []scanner.Finding) error {
	ctx := context.Background()
	iterator, err := persistedReportIteratorContext(ctx, shadow)
	if err != nil {
		return fmt.Errorf("prepare persisted JSON iterator: %w", err)
	}
	state, err := newJSONSQLiteState()
	if err != nil {
		return err
	}
	defer state.close()
	if err := iterator(ctx, func(f scanner.Finding) error { return state.ingest(ctx, f) }); err != nil {
		return fmt.Errorf("populate persisted JSON state: %w", err)
	}
	categories, err := state.categorySummaries(ctx)
	if err != nil {
		return fmt.Errorf("aggregate JSON categories: %w", err)
	}
	if err := state.prepareAccessPaths(ctx); err != nil {
		return fmt.Errorf("aggregate JSON access paths: %w", err)
	}
	var unique int
	if err := state.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_findings`).Scan(&unique); err != nil {
		return err
	}
	summary := j.summary.Snapshot()
	summary.MatchesFound += unique - state.rawCount
	performance := diff.PerformanceSummary{FilesScanned: summary.FilesScanned, FindingsTotal: summary.MatchesFound, DurationMS: summary.EndedAt.Sub(summary.StartedAt).Milliseconds()}
	if performance.DurationMS > 0 {
		performance.FilesPerSecond = float64(summary.FilesScanned) / float64(performance.DurationMS) * 1000
	}
	performance.ClassificationDistribution, err = state.classificationDistribution(ctx)
	if err != nil {
		return fmt.Errorf("aggregate JSON classification distribution: %w", err)
	}
	validation, err := buildValidationSummaryIterator(j.manifest, func(visit func(scanner.Finding) error) error {
		return iterator(ctx, visit)
	})
	if err != nil {
		return fmt.Errorf("validate persisted JSON findings: %w", err)
	}
	var diffSummary *jsonDiffSummary
	status := func(scanner.Finding) diff.FindingDelta { return diff.FindingDelta{} }
	if len(baseline) > 0 {
		baselineByFingerprint := make(map[diff.FindingFingerprint]scanner.Finding, len(baseline))
		for _, finding := range baseline {
			baselineByFingerprint[diff.Fingerprint(finding)] = finding
		}
		seen := make(map[diff.FindingFingerprint]struct{})
		var counts diff.Summary
		rows, queryErr := state.db.QueryContext(ctx, `SELECT payload FROM report_fingerprints ORDER BY fingerprint`)
		if queryErr != nil {
			return queryErr
		}
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				_ = rows.Close()
				return err
			}
			var finding scanner.Finding
			if err := json.Unmarshal(payload, &finding); err != nil {
				_ = rows.Close()
				return err
			}
			fp := diff.Fingerprint(finding)
			seen[fp] = struct{}{}
			if previous, ok := baselineByFingerprint[fp]; ok {
				result := diff.Compare([]scanner.Finding{previous}, []scanner.Finding{finding})
				switch {
				case len(result.Changed) > 0:
					counts.Changed++
				case len(result.Unchanged) > 0:
					counts.Unchanged++
				}
			} else {
				counts.New++
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		counts.Removed = len(baselineByFingerprint) - len(seenIntersection(seen, baselineByFingerprint))
		diffSummary = &jsonDiffSummary{New: counts.New, Removed: counts.Removed, Changed: counts.Changed, Unchanged: counts.Unchanged}
		status = func(finding scanner.Finding) diff.FindingDelta {
			previous, ok := baselineByFingerprint[diff.Fingerprint(finding)]
			if !ok {
				return diff.FindingDelta{Status: diff.StatusNew, Fingerprint: diff.Fingerprint(finding)}
			}
			result := diff.Compare([]scanner.Finding{previous}, []scanner.Finding{finding})
			if len(result.Changed) > 0 {
				return diff.FindingDelta{Status: diff.StatusChanged, Fingerprint: diff.Fingerprint(finding), ChangedFields: result.Changed[0].ChangedFields}
			}
			return diff.FindingDelta{Status: diff.StatusUnchanged, Fingerprint: diff.Fingerprint(finding)}
		}
	}
	metadata := map[string]any{
		"profile": strings.TrimSpace(j.profile), "summary": summary, "metrics": j.metrics, "category_summaries": categories,
		"suppression": j.suppression, "backup_artifact_inventory": j.backupArtifacts.Snapshot(),
		"performance": performanceSummaryToJSON(performance), "performance_comparison": performanceComparisonToJSON(buildPerformanceComparison(performance, j.baselinePerformance)),
		"validation_mode": j.validationMode.Summary(summary), "validation": validation, "credential_analysis": analyzeCandidates(nil, j.candidates),
	}
	if diffSummary != nil {
		metadata["diff_summary"] = diffSummary
	}
	if err := writeJSONMetadata(j.w, metadata); err != nil {
		return err
	}
	if _, err := io.WriteString(j.w, `,"access_paths":`); err != nil {
		return err
	}
	if err := state.writeAccessPaths(ctx, j.w); err != nil {
		return err
	}
	if _, err := io.WriteString(j.w, `,"findings":`); err != nil {
		return err
	}
	if err := state.writeFindings(ctx, j.w, j.pretty, status); err != nil {
		return err
	}
	if _, err := io.WriteString(j.w, "}\n"); err != nil {
		return err
	}
	if atomic, ok := j.closer.(*atomicOutput); ok {
		atomic.commit = true
	}
	if j.closer != nil {
		return j.closer.Close()
	}
	return nil
}

func seenIntersection(left map[diff.FindingFingerprint]struct{}, right map[diff.FindingFingerprint]scanner.Finding) map[diff.FindingFingerprint]struct{} {
	result := make(map[diff.FindingFingerprint]struct{})
	for key := range left {
		if _, ok := right[key]; ok {
			result[key] = struct{}{}
		}
	}
	return result
}

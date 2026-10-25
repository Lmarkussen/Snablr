package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

func writeMarkdownFinding(w io.Writer, finding scanner.Finding) error {
	snippet := firstNonEmpty(finding.Context, finding.Snippet)
	if snippet == "" {
		snippet = firstNonEmpty(finding.MatchedText, finding.Match)
	}
	ruleLabel := finding.RuleName
	if strings.TrimSpace(ruleLabel) == "" {
		ruleLabel = finding.RuleID
	}
	shareLabel := valueOrDash(finding.Share)
	if finding.ShareType != "" {
		shareLabel += " (" + finding.ShareType + ")"
	}
	if finding.ShareDescription != "" {
		shareLabel += " - " + finding.ShareDescription
	}
	_, err := fmt.Fprintf(w, "| %s | %s | %s | %s | `%s` | %s |\n",
		escapeMD(strings.ToUpper(finding.Severity)), escapeMD(ruleLabel), escapeMD(valueOrDash(finding.Host)), escapeMD(shareLabel), strings.ReplaceAll(finding.FilePath, "`", "'"), escapeMD(snippet))
	return err
}

func closeMarkdownSQLiteStreaming(m *MarkdownWriter, shadow *store.SQLiteStore) error {
	ctx := context.Background()
	iterator, err := persistedReportIteratorContext(ctx, shadow)
	if err != nil {
		return fmt.Errorf("prepare persisted Markdown iterator: %w", err)
	}
	state, err := newJSONSQLiteState()
	if err != nil {
		return err
	}
	defer state.close()
	if err := iterator(ctx, func(f scanner.Finding) error { return state.ingest(ctx, f) }); err != nil {
		return fmt.Errorf("populate persisted Markdown state: %w", err)
	}
	categories, err := state.categorySummaries(ctx)
	if err != nil {
		return fmt.Errorf("aggregate Markdown categories: %w", err)
	}
	var unique int
	if err := state.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_findings`).Scan(&unique); err != nil {
		return err
	}
	summary := m.summary.Snapshot()
	summary.MatchesFound += unique - state.rawCount
	if _, err := fmt.Fprintln(m.w, "# Snablr Scan Summary"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(m.w, "\nGenerated: `%s`\n", summary.EndedAt.Format(timeFormat)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(m.w, "\n## Summary"); err != nil {
		return err
	}
	for _, line := range []string{
		fmt.Sprintf("- Hosts scanned: %d", summary.HostsScanned), fmt.Sprintf("- Shares scanned: %d", summary.SharesScanned), fmt.Sprintf("- Files scanned: %d", summary.FilesScanned), fmt.Sprintf("- Files skipped: %d", summary.SkippedFiles), fmt.Sprintf("- Matches found: %d", summary.MatchesFound), fmt.Sprintf("- Read errors: %d", summary.ReadErrors), fmt.Sprintf("- Targets reachable: %d", m.metrics.Counters.TargetsReachable), fmt.Sprintf("- Incremental discovered: %d", m.metrics.Counters.IncrementalDiscovered), fmt.Sprintf("- Incremental inspected: %d", m.metrics.Counters.IncrementalInspected), fmt.Sprintf("- Incremental skipped unchanged: %d", m.metrics.Counters.IncrementalSkippedUnchanged), fmt.Sprintf("- Incremental rescanned changed: %d", m.metrics.Counters.IncrementalRescannedChanged), fmt.Sprintf("- Incremental retried: %d", m.metrics.Counters.IncrementalRetried), fmt.Sprintf("- Incremental newly accessible known: %d", m.metrics.Counters.IncrementalNewAccessible),
	} {
		if _, err := fmt.Fprintln(m.w, line); err != nil {
			return err
		}
	}
	if len(categories) > 0 {
		if _, err := fmt.Fprintln(m.w, "\n## Categories\n\n| Category | Findings | Highest Severity | Guidance |\n| --- | ---: | --- | --- |"); err != nil {
			return err
		}
		for _, category := range categories {
			if _, err := fmt.Fprintf(m.w, "| %s | %d | %s | %s |\n", escapeMD(category.Category), category.Findings, escapeMD(category.HighestSeverity), escapeMD(category.RemediationGuidance)); err != nil {
				return err
			}
		}
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM report_findings`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		if _, err := fmt.Fprintln(m.w, "\n## Findings\n\n| Severity | Rule | Host | Share | File Path | Match Snippet |\n| --- | --- | --- | --- | --- | --- |"); err != nil {
			return err
		}
		rows, err := state.db.QueryContext(ctx, `SELECT payload FROM report_findings ORDER BY severity DESC,host,share,file_path,rule_id,dedup_key`)
		if err != nil {
			return err
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
			if err := writeMarkdownFinding(m.w, finding); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	if atomic, ok := m.closer.(*atomicOutput); ok {
		atomic.commit = true
	}
	if m.closer != nil {
		return m.closer.Close()
	}
	return nil
}

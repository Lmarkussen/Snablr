package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type MarkdownWriter struct {
	closer   io.Closer
	findings []scanner.Finding
	mu       sync.Mutex
	metrics  metrics.Snapshot
	summary  *summaryCollector
	w        io.Writer
}

func NewMarkdownWriter(w io.Writer, closer io.Closer) *MarkdownWriter {
	return &MarkdownWriter{
		w:       w,
		closer:  closer,
		summary: newSummaryCollector(),
	}
}

func (m *MarkdownWriter) WriteFinding(f scanner.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.summary.RecordFinding(f)
	m.findings = append(m.findings, f)
	return nil
}

func (m *MarkdownWriter) RecordHost(host string) {
	m.summary.RecordHost(host)
}

func (m *MarkdownWriter) RecordShare(host, share string) {
	m.summary.RecordShare(host, share)
}

func (m *MarkdownWriter) RecordFile(meta scanner.FileMetadata) {
	m.summary.RecordFile(meta)
}

func (m *MarkdownWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	m.summary.RecordSkip(meta, reason)
}

func (m *MarkdownWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	m.summary.RecordReadError(meta, err)
}

func (m *MarkdownWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = snapshot
}

func (m *MarkdownWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	augmented := augmentFindingsForReporting(m.findings)
	summary := adjustedSummarySnapshot(m.summary.Snapshot(), m.findings, augmented)
	categorySummaries := buildCategorySummaries(augmented)
	sort.Slice(augmented, func(i, j int) bool {
		left := severityRank(augmented[i].Severity)
		right := severityRank(augmented[j].Severity)
		if left == right {
			if augmented[i].Host == augmented[j].Host {
				if augmented[i].Share == augmented[j].Share {
					return augmented[i].FilePath < augmented[j].FilePath
				}
				return augmented[i].Share < augmented[j].Share
			}
			return augmented[i].Host < augmented[j].Host
		}
		return left > right
	})

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
		fmt.Sprintf("- Hosts scanned: %d", summary.HostsScanned),
		fmt.Sprintf("- Shares scanned: %d", summary.SharesScanned),
		fmt.Sprintf("- Files scanned: %d", summary.FilesScanned),
		fmt.Sprintf("- Files skipped: %d", summary.SkippedFiles),
		fmt.Sprintf("- Matches found: %d", summary.MatchesFound),
		fmt.Sprintf("- Read errors: %d", summary.ReadErrors),
		fmt.Sprintf("- Targets reachable: %d", m.metrics.Counters.TargetsReachable),
	} {
		if _, err := fmt.Fprintln(m.w, line); err != nil {
			return err
		}
	}

	if len(categorySummaries) > 0 {
		if _, err := fmt.Fprintln(m.w, "\n## Categories"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(m.w, "\n| Category | Findings | Highest Severity | Guidance |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(m.w, "| --- | ---: | --- | --- |"); err != nil {
			return err
		}
		for _, category := range categorySummaries {
			if _, err := fmt.Fprintf(m.w, "| %s | %d | %s | %s |\n",
				escapeMD(category.Category),
				category.Findings,
				escapeMD(category.HighestSeverity),
				escapeMD(category.RemediationGuidance),
			); err != nil {
				return err
			}
		}
	}

	if len(augmented) > 0 {
		if _, err := fmt.Fprintln(m.w, "\n## Findings"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(m.w, "\n| Severity | Rule | Host | Share | File Path | Match Snippet |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(m.w, "| --- | --- | --- | --- | --- | --- |"); err != nil {
			return err
		}
		for _, finding := range augmented {
			snippet := firstNonEmpty(finding.Context, finding.Snippet)
			if snippet == "" {
				snippet = firstNonEmpty(finding.MatchedText, finding.Match, finding.MatchedTextRedacted)
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
			if _, err := fmt.Fprintf(m.w, "| %s | %s | %s | %s | `%s` | %s |\n",
				escapeMD(strings.ToUpper(finding.Severity)),
				escapeMD(ruleLabel),
				escapeMD(valueOrDash(finding.Host)),
				escapeMD(shareLabel),
				strings.ReplaceAll(finding.FilePath, "`", "'"),
				escapeMD(snippet),
			); err != nil {
				return err
			}
		}
	}

	if m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

func escapeMD(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ")
	return replacer.Replace(strings.TrimSpace(value))
}

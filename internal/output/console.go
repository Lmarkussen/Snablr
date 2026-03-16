package output

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type ConsoleWriter struct {
	w       io.Writer
	closer  io.Closer
	mu      sync.Mutex
	metrics metrics.Snapshot
	summary *summaryCollector
}

func NewConsoleWriter(w io.Writer, closer io.Closer) *ConsoleWriter {
	return &ConsoleWriter{
		w:       w,
		closer:  closer,
		summary: newSummaryCollector(),
	}
}

func (c *ConsoleWriter) WriteFinding(f scanner.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.summary.RecordFinding(f)

	if _, err := fmt.Fprintf(c.w, "[%s] %s\n", strings.ToUpper(f.Severity), f.RuleID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Host: %s\n", valueOrDash(f.Host)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Share: %s\n", valueOrDash(f.Share)); err != nil {
		return err
	}
	if f.ShareType != "" {
		if _, err := fmt.Fprintf(c.w, "Share Type: %s\n", f.ShareType); err != nil {
			return err
		}
	}
	if f.ShareDescription != "" {
		if _, err := fmt.Fprintf(c.w, "Share Description: %s\n", f.ShareDescription); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Source: %s\n", valueOrDash(f.Source)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "File: %s\n", uncPath(f)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Rule: %s\n", f.RuleName); err != nil {
		return err
	}
	if f.Confidence != "" {
		if _, err := fmt.Fprintf(c.w, "Confidence: %s", strings.ToUpper(f.Confidence)); err != nil {
			return err
		}
		if f.ConfidenceScore > 0 {
			if _, err := fmt.Fprintf(c.w, " (%d)", f.ConfidenceScore); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(c.w); err != nil {
			return err
		}
	}
	if len(f.MatchedRuleIDs) > 0 {
		if _, err := fmt.Fprintf(c.w, "Matched Rules: %s\n", strings.Join(f.MatchedRuleIDs, ", ")); err != nil {
			return err
		}
	}
	if len(f.MatchedSignalTypes) > 0 {
		if _, err := fmt.Fprintf(c.w, "Signals: %s\n", strings.Join(f.MatchedSignalTypes, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Signal: %s\n", valueOrDash(primarySignalType(f))); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "Category: %s\n", valueOrDash(f.Category)); err != nil {
		return err
	}
	if f.FromSYSVOL || f.FromNETLOGON {
		label := "NETLOGON"
		if f.FromSYSVOL {
			label = "SYSVOL"
		}
		if _, err := fmt.Fprintf(c.w, "AD Share: %s\n", label); err != nil {
			return err
		}
	}
	if f.DFSNamespacePath != "" {
		if _, err := fmt.Fprintf(c.w, "DFS Namespace: %s\n", f.DFSNamespacePath); err != nil {
			return err
		}
	}
	if f.DFSLinkPath != "" {
		if _, err := fmt.Fprintf(c.w, "DFS Link: %s\n", f.DFSLinkPath); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, "Tags: %s\n", tagsOrDash(f.Tags)); err != nil {
		return err
	}
	for _, line := range consoleEvidenceLines(f) {
		if _, err := fmt.Fprintln(c.w, line); err != nil {
			return err
		}
	}
	if f.MatchReason != "" {
		if _, err := fmt.Fprintf(c.w, "Why It Matched: %s\n", f.MatchReason); err != nil {
			return err
		}
	}
	if len(f.ConfidenceReasons) > 0 {
		if _, err := fmt.Fprintf(c.w, "Confidence Raised By: %s\n", strings.Join(limitStrings(f.ConfidenceReasons, 3), "; ")); err != nil {
			return err
		}
	}
	if f.RuleExplanation != "" {
		if _, err := fmt.Fprintf(c.w, "Rule Note: %s\n", f.RuleExplanation); err != nil {
			return err
		}
	}
	guidance := f.RuleRemediation
	if guidance == "" {
		guidance = remediationGuidanceForCategory(f.Category)
	}
	if guidance != "" {
		if _, err := fmt.Fprintf(c.w, "Remediation: %s\n", guidance); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(c.w)
	return err
}

func limitStrings(values []string, max int) []string {
	if len(values) <= max || max <= 0 {
		return values
	}
	return values[:max]
}

func (c *ConsoleWriter) RecordHost(host string) {
	c.summary.RecordHost(host)
}

func (c *ConsoleWriter) RecordShare(host, share string) {
	c.summary.RecordShare(host, share)
}

func (c *ConsoleWriter) RecordFile(meta scanner.FileMetadata) {
	c.summary.RecordFile(meta)
}

func (c *ConsoleWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	c.summary.RecordSkip(meta, reason)
}

func (c *ConsoleWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	c.summary.RecordReadError(meta, err)
}

func (c *ConsoleWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = snapshot
}

func (c *ConsoleWriter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := c.summary.Snapshot()
	if _, err := fmt.Fprintf(c.w, "Summary: hosts=%d shares=%d files=%d matches=%d skipped=%d read_errors=%d started=%s ended=%s\n",
		snapshot.HostsScanned,
		snapshot.SharesScanned,
		snapshot.FilesScanned,
		snapshot.MatchesFound,
		snapshot.SkippedFiles,
		snapshot.ReadErrors,
		snapshot.StartedAt.Format(timeFormat),
		snapshot.EndedAt.Format(timeFormat),
	); err != nil {
		return err
	}
	if c.metrics.Counters.TargetsLoaded > 0 || c.metrics.Counters.TargetsReachable > 0 || c.metrics.Counters.SharesEnumerated > 0 {
		if _, err := fmt.Fprintf(c.w, "Metrics: targets_loaded=%d targets_reachable=%d shares_enumerated=%d files_visited=%d files_skipped=%d files_read=%d matches_found=%d\n",
			c.metrics.Counters.TargetsLoaded,
			c.metrics.Counters.TargetsReachable,
			c.metrics.Counters.SharesEnumerated,
			c.metrics.Counters.FilesVisited,
			c.metrics.Counters.FilesSkipped,
			c.metrics.Counters.FilesRead,
			c.metrics.Counters.MatchesFound,
		); err != nil {
			return err
		}
	}
	if len(c.metrics.Phases) > 0 {
		if _, err := fmt.Fprintln(c.w, "Phase Timings:"); err != nil {
			return err
		}
		for _, phase := range c.metrics.Phases {
			if _, err := fmt.Fprintf(c.w, "  %s: %dms\n", phase.Name, phase.DurationMS); err != nil {
				return err
			}
		}
	}

	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

func consoleEvidenceLines(f scanner.Finding) []string {
	signalType := primarySignalType(f)
	switch signalType {
	case "content":
		lines := make([]string, 0, 5)
		if f.LineNumber > 0 {
			lines = append(lines, fmt.Sprintf("Line: %d", f.LineNumber))
		}
		if f.PotentialAccount != "" {
			lines = append(lines, fmt.Sprintf("Potential account context: %s", f.PotentialAccount))
		}
		if value := firstNonEmpty(f.MatchedTextRedacted, f.Match); value != "" {
			lines = append(lines, fmt.Sprintf("Matched text: %s", value))
		}
		if value := firstNonEmpty(f.ContextRedacted, f.Snippet); value != "" {
			lines = append(lines, "Context:")
			for _, rawLine := range strings.Split(value, "\n") {
				lines = append(lines, "  "+rawLine)
			}
		}
		return lines
	case "filename":
		if value := firstNonEmpty(f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched filename token: %s", value)}
		}
	case "extension":
		if value := firstNonEmpty(f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched extension: %s", value)}
		}
	case "path", "directory":
		if value := firstNonEmpty(f.MatchedTextRedacted, f.Match); value != "" {
			return []string{fmt.Sprintf("Matched %s token: %s", signalType, value)}
		}
	}

	if value := firstNonEmpty(f.MatchedTextRedacted, f.Match); value != "" {
		return []string{fmt.Sprintf("Matched value: %s", value)}
	}
	if f.Snippet != "" {
		return []string{fmt.Sprintf("Snippet: %s", f.Snippet)}
	}
	return nil
}

func primarySignalType(f scanner.Finding) string {
	if strings.TrimSpace(f.SignalType) != "" {
		return strings.TrimSpace(f.SignalType)
	}
	if len(f.MatchedSignalTypes) > 0 {
		return strings.TrimSpace(f.MatchedSignalTypes[0])
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

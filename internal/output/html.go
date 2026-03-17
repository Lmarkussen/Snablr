package output

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/planner"
	"snablr/internal/scanner"
	"snablr/internal/version"
)

//go:embed templates/report.html.tmpl
var reportTemplates embed.FS

type HTMLWriter struct {
	closer   io.Closer
	findings []scanner.Finding
	baseline []scanner.Finding
	mu       sync.Mutex
	metrics  metrics.Snapshot
	summary  *summaryCollector
	template *template.Template
	manifest string
	w        io.Writer
}

type htmlCategoryGroup struct {
	Summary  categorySummary
	Findings []htmlFinding
}

type htmlFinding struct {
	Finding       scanner.Finding
	DiffStatus    string
	ChangedFields []string
}

type hostSummary struct {
	Host            string
	Findings        int
	Shares          int
	Categories      int
	HighestSeverity string
	FromLDAP        bool
	FromDFS         bool
	FromSYSVOL      bool
	FromNETLOGON    bool
}

type severitySummary struct {
	Severity string
	Count    int
}

type reportFilterOptions struct {
	Categories []string
	Sources    []string
	Signals    []string
	Scopes     []string
}

func NewHTMLWriter(w io.Writer, closer io.Closer) (*HTMLWriter, error) {
	tmpl, err := template.New("report.html.tmpl").Funcs(template.FuncMap{
		"joinTags":          strings.Join,
		"joinList":          strings.Join,
		"severityClass":     severityClass,
		"confidenceClass":   confidenceClass,
		"priorityClass":     priorityClass,
		"priorityLabel":     priorityLabel,
		"sourceClass":       sourceClass,
		"diffClass":         diffClass,
		"diffLabel":         diffLabel,
		"signalLabel":       signalLabel,
		"signalClass":       signalClass,
		"primarySignal":     primarySignal,
		"signalMatchLabel":  signalMatchLabel,
		"truncatePath":      truncatePath,
		"uncPath":           uncPath,
		"valueOrDash":       valueOrDash,
		"displayMatch":      displayMatch,
		"displayContext":    displayContext,
		"displayRawMatch":   displayRawMatch,
		"displayRawContext": displayRawContext,
		"isHeuristicHit":    isHeuristicHit,
		"formatScanTime":    formatScanTime,
		"formatDuration":    formatDuration,
		"triageClass":       triageClass,
		"triageLabel":       triageLabel,
		"isActionable":      isActionable,
		"isCorrelated":      isCorrelated,
		"normalizedSource":  normalizedSourceLabel,
		"slug":              slug,
	}).ParseFS(reportTemplates, "templates/report.html.tmpl")
	if err != nil {
		return nil, err
	}

	return &HTMLWriter{
		w:        w,
		closer:   closer,
		summary:  newSummaryCollector(),
		template: tmpl,
	}, nil
}

func (h *HTMLWriter) WriteFinding(f scanner.Finding) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.summary.RecordFinding(f)
	h.findings = append(h.findings, f)
	return nil
}

func (h *HTMLWriter) RecordHost(host string) {
	h.summary.RecordHost(host)
}

func (h *HTMLWriter) RecordShare(host, share string) {
	h.summary.RecordShare(host, share)
}

func (h *HTMLWriter) RecordFile(meta scanner.FileMetadata) {
	h.summary.RecordFile(meta)
}

func (h *HTMLWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	h.summary.RecordSkip(meta, reason)
}

func (h *HTMLWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	h.summary.RecordReadError(meta, err)
}

func (h *HTMLWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metrics = snapshot
}

func (h *HTMLWriter) SetBaselineFindings(findings []scanner.Finding) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.baseline = cloneFindings(findings)
}

func (h *HTMLWriter) SetValidationManifest(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.manifest = path
}

func (h *HTMLWriter) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	augmented := augmentFindingsForReporting(h.findings)
	categorySummaries := buildCategorySummaries(augmented)
	var diffResult *diff.DiffResult
	statuses := map[diff.FindingFingerprint]diff.FindingDelta{}
	if len(h.baseline) > 0 {
		result := diff.Compare(h.baseline, augmented)
		diffResult = &result
		statuses = diff.CurrentStatuses(result)
	}
	categoryGroups := groupFindingsByCategory(augmented, categorySummaries, statuses)
	hostSummaries := buildHostSummaries(augmented)
	severitySummaries := buildSeveritySummaries(augmented)
	filterOptions := buildFilterOptions(augmented)
	summary := adjustedSummarySnapshot(h.summary.Snapshot(), h.findings, augmented)
	validation, err := buildValidationSummary(h.manifest, augmented)
	if err != nil {
		if h.closer != nil {
			_ = h.closer.Close()
		}
		return err
	}

	data := struct {
		Version           string
		Summary           summarySnapshot
		Metrics           metrics.Snapshot
		SeveritySummaries []severitySummary
		CategorySummaries []categorySummary
		HostSummaries     []hostSummary
		DiffSummary       *diff.Summary
		ChangedFindings   []diff.ChangedFinding
		RemovedFindings   []scanner.Finding
		CategoryGroups    []htmlCategoryGroup
		FilterOptions     reportFilterOptions
		Validation        *validationSummary
	}{
		Version:           version.Short(),
		Summary:           summary,
		Metrics:           h.metrics,
		SeveritySummaries: severitySummaries,
		CategorySummaries: categorySummaries,
		HostSummaries:     hostSummaries,
		DiffSummary:       diffSummary(diffResult),
		ChangedFindings:   changedFindings(diffResult),
		RemovedFindings:   removedFindings(diffResult),
		CategoryGroups:    categoryGroups,
		FilterOptions:     filterOptions,
		Validation:        validation,
	}

	if err := h.template.ExecuteTemplate(h.w, "report.html.tmpl", data); err != nil {
		if h.closer != nil {
			_ = h.closer.Close()
		}
		return err
	}
	if h.closer == nil {
		return nil
	}
	return h.closer.Close()
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func severityClass(value string) string {
	switch strings.ToLower(value) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-unknown"
	}
}

func confidenceClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "conf-high"
	case "medium":
		return "conf-medium"
	case "low":
		return "conf-low"
	default:
		return "conf-unknown"
	}
}

func signalLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "validated":
		return "validated"
	case "content":
		return "content"
	case "filename":
		return "filename"
	case "extension":
		return "extension"
	case "path":
		return "path"
	case "share_priority":
		return "share priority"
	case "planner_priority":
		return "planner priority"
	case "correlation":
		return "correlation"
	default:
		return value
	}
}

func signalClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "validated":
		return "signal-validated"
	case "content":
		return "signal-content"
	case "filename":
		return "signal-filename"
	case "extension":
		return "signal-extension"
	case "path":
		return "signal-path"
	case "correlation":
		return "signal-validated"
	case "directory":
		return "signal-directory"
	default:
		return "signal-generic"
	}
}

func primarySignal(f scanner.Finding) string {
	if strings.TrimSpace(f.SignalType) != "" {
		return strings.TrimSpace(f.SignalType)
	}
	if len(f.MatchedSignalTypes) > 0 {
		return strings.TrimSpace(f.MatchedSignalTypes[0])
	}
	return ""
}

func signalMatchLabel(signal string) string {
	switch strings.ToLower(strings.TrimSpace(signal)) {
	case "content":
		return "Matched text"
	case "filename":
		return "Matched filename token"
	case "extension":
		return "Matched extension"
	case "path":
		return "Matched path token"
	case "correlation":
		return "Correlated evidence"
	case "directory":
		return "Matched directory token"
	default:
		return "Matched value"
	}
}

func displayMatch(f scanner.Finding) string {
	if strings.TrimSpace(f.MatchedText) != "" {
		return strings.TrimSpace(f.MatchedText)
	}
	if strings.TrimSpace(f.MatchedTextRedacted) != "" {
		return strings.TrimSpace(f.MatchedTextRedacted)
	}
	return strings.TrimSpace(f.Match)
}

func displayRawMatch(f scanner.Finding) string {
	if strings.TrimSpace(f.MatchedText) != "" {
		return strings.TrimSpace(f.MatchedText)
	}
	return strings.TrimSpace(f.Match)
}

func displayContext(f scanner.Finding) string {
	if strings.TrimSpace(f.Context) != "" {
		return strings.TrimSpace(f.Context)
	}
	if strings.TrimSpace(f.ContextRedacted) != "" {
		return strings.TrimSpace(f.ContextRedacted)
	}
	return strings.TrimSpace(f.Snippet)
}

func displayRawContext(f scanner.Finding) string {
	if strings.TrimSpace(f.Context) != "" {
		return strings.TrimSpace(f.Context)
	}
	return strings.TrimSpace(f.Snippet)
}

func isHeuristicHit(f scanner.Finding) bool {
	switch strings.ToLower(strings.TrimSpace(primarySignal(f))) {
	case "filename", "extension", "path", "directory":
		return true
	default:
		return false
	}
}

func triageClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "actionable":
		return "triage-actionable"
	case "config-only":
		return "triage-config"
	case "weak-review":
		return "triage-weak"
	default:
		return "triage-unknown"
	}
}

func triageLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "actionable":
		return "actionable"
	case "config-only":
		return "config only"
	case "weak-review":
		return "weak review"
	default:
		return valueOrDash(value)
	}
}

func isActionable(f scanner.Finding) bool {
	return f.Actionable
}

func isCorrelated(f scanner.Finding) bool {
	return f.Correlated
}

func normalizedSourceLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return strings.ToLower(value)
}

func truncatePath(value string) string {
	if len(value) <= 72 {
		return value
	}
	return value[:69] + "..."
}

func formatScanTime(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.Format(timeFormat)
}

func formatDuration(start, end time.Time) string {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return "-"
	}

	d := end.Sub(start).Round(time.Second)
	if d < time.Second {
		return "0s"
	}

	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	parts := make([]string, 0, 3)
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, " ")
}

func buildFilterOptions(findings []scanner.Finding) reportFilterOptions {
	categories := make(map[string]struct{})
	sources := make(map[string]struct{})
	signals := make(map[string]struct{})
	scopes := make(map[string]struct{})

	for _, finding := range findings {
		if value := strings.TrimSpace(finding.Category); value != "" {
			categories[value] = struct{}{}
		}
		sources[normalizedSourceLabel(finding.Source)] = struct{}{}
		if value := strings.TrimSpace(primarySignal(finding)); value != "" {
			signals[strings.ToLower(value)] = struct{}{}
		}
		if value := strings.TrimSpace(finding.Host); value != "" {
			scopes[value] = struct{}{}
		}
		if value := strings.TrimSpace(finding.Share); value != "" {
			scopes[value] = struct{}{}
		}
	}

	return reportFilterOptions{
		Categories: sortedMapKeys(categories),
		Sources:    sortedMapKeys(sources),
		Signals:    sortedMapKeys(signals),
		Scopes:     sortedMapKeys(scopes),
	}
}

func sortedMapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func buildSeveritySummaries(findings []scanner.Finding) []severitySummary {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"unknown":  0,
	}
	for _, finding := range findings {
		key := strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, ok := counts[key]; !ok {
			key = "unknown"
		}
		counts[key]++
	}
	return []severitySummary{
		{Severity: "critical", Count: counts["critical"]},
		{Severity: "high", Count: counts["high"]},
		{Severity: "medium", Count: counts["medium"]},
		{Severity: "low", Count: counts["low"]},
		{Severity: "unknown", Count: counts["unknown"]},
	}
}

func priorityClass(value int) string {
	switch planner.PriorityBand(value) {
	case "critical":
		return "prio-critical"
	case "high":
		return "prio-high"
	case "medium":
		return "prio-medium"
	default:
		return "prio-low"
	}
}

func priorityLabel(value int) string {
	switch planner.PriorityBand(value) {
	case "critical":
		return "priority critical"
	case "high":
		return "priority high"
	case "medium":
		return "priority medium"
	default:
		return "priority low"
	}
}

func sourceClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ldap":
		return "source-ldap"
	case "dfs":
		return "source-dfs"
	case "cli":
		return "source-cli"
	case "file":
		return "source-file"
	default:
		return "source-generic"
	}
}

func diffClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(diff.StatusNew):
		return "diff-new"
	case string(diff.StatusChanged):
		return "diff-changed"
	case string(diff.StatusRemoved):
		return "diff-removed"
	case string(diff.StatusUnchanged):
		return "diff-unchanged"
	default:
		return "diff-unknown"
	}
}

func diffLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(diff.StatusNew):
		return "new"
	case string(diff.StatusChanged):
		return "changed"
	case string(diff.StatusRemoved):
		return "removed"
	case string(diff.StatusUnchanged):
		return "unchanged"
	default:
		return "current"
	}
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "uncategorized"
	}
	var b strings.Builder
	prevDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "uncategorized"
	}
	return out
}

func groupFindingsByCategory(findings []scanner.Finding, summaries []categorySummary, statuses map[diff.FindingFingerprint]diff.FindingDelta) []htmlCategoryGroup {
	if len(findings) == 0 {
		return nil
	}

	buckets := make(map[string][]htmlFinding)
	for _, finding := range findings {
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			category = "uncategorized"
		}
		delta := statuses[diff.Fingerprint(finding)]
		buckets[category] = append(buckets[category], htmlFinding{
			Finding:       finding,
			DiffStatus:    string(delta.Status),
			ChangedFields: append([]string{}, delta.ChangedFields...),
		})
	}

	groups := make([]htmlCategoryGroup, 0, len(summaries))
	for _, summary := range summaries {
		groupFindings := append([]htmlFinding{}, buckets[summary.Category]...)
		sort.Slice(groupFindings, func(i, j int) bool {
			left := severityRank(groupFindings[i].Finding.Severity)
			right := severityRank(groupFindings[j].Finding.Severity)
			if left == right {
				if diffStatusRank(groupFindings[i].DiffStatus) == diffStatusRank(groupFindings[j].DiffStatus) {
					if groupFindings[i].Finding.Host == groupFindings[j].Finding.Host {
						if groupFindings[i].Finding.Share == groupFindings[j].Finding.Share {
							return groupFindings[i].Finding.FilePath < groupFindings[j].Finding.FilePath
						}
						return groupFindings[i].Finding.Share < groupFindings[j].Finding.Share
					}
					return groupFindings[i].Finding.Host < groupFindings[j].Finding.Host
				}
				return diffStatusRank(groupFindings[i].DiffStatus) < diffStatusRank(groupFindings[j].DiffStatus)
			}
			return left > right
		})
		groups = append(groups, htmlCategoryGroup{
			Summary:  summary,
			Findings: groupFindings,
		})
	}

	return groups
}

func diffStatusRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(diff.StatusNew):
		return 0
	case string(diff.StatusChanged):
		return 1
	case string(diff.StatusUnchanged):
		return 2
	default:
		return 3
	}
}

func diffSummary(result *diff.DiffResult) *diff.Summary {
	if result == nil {
		return nil
	}
	summary := result.Summary()
	return &summary
}

func changedFindings(result *diff.DiffResult) []diff.ChangedFinding {
	if result == nil {
		return nil
	}
	return append([]diff.ChangedFinding{}, result.Changed...)
}

func removedFindings(result *diff.DiffResult) []scanner.Finding {
	if result == nil {
		return nil
	}
	return append([]scanner.Finding{}, result.Removed...)
}

func buildHostSummaries(findings []scanner.Finding) []hostSummary {
	if len(findings) == 0 {
		return nil
	}

	type hostBucket struct {
		summary    hostSummary
		shares     map[string]struct{}
		categories map[string]struct{}
	}

	buckets := make(map[string]*hostBucket)
	for _, finding := range findings {
		host := strings.TrimSpace(finding.Host)
		if host == "" {
			host = "unknown-host"
		}

		bucket, ok := buckets[host]
		if !ok {
			bucket = &hostBucket{
				summary: hostSummary{
					Host: host,
				},
				shares:     make(map[string]struct{}),
				categories: make(map[string]struct{}),
			}
			buckets[host] = bucket
		}

		bucket.summary.Findings++
		if severityRank(finding.Severity) > severityRank(bucket.summary.HighestSeverity) {
			bucket.summary.HighestSeverity = finding.Severity
		}
		if strings.TrimSpace(finding.Share) != "" {
			bucket.shares[finding.Share] = struct{}{}
		}
		category := strings.TrimSpace(finding.Category)
		if category != "" {
			bucket.categories[category] = struct{}{}
		}
		if strings.EqualFold(strings.TrimSpace(finding.Source), "ldap") {
			bucket.summary.FromLDAP = true
		}
		if strings.EqualFold(strings.TrimSpace(finding.Source), "dfs") {
			bucket.summary.FromDFS = true
		}
		if finding.FromSYSVOL {
			bucket.summary.FromSYSVOL = true
		}
		if finding.FromNETLOGON {
			bucket.summary.FromNETLOGON = true
		}
	}

	out := make([]hostSummary, 0, len(buckets))
	for _, bucket := range buckets {
		bucket.summary.Shares = len(bucket.shares)
		bucket.summary.Categories = len(bucket.categories)
		if strings.TrimSpace(bucket.summary.HighestSeverity) == "" {
			bucket.summary.HighestSeverity = "unknown"
		}
		out = append(out, bucket.summary)
	}

	sort.Slice(out, func(i, j int) bool {
		left := severityRank(out[i].HighestSeverity)
		right := severityRank(out[j].HighestSeverity)
		if left == right {
			if out[i].Findings == out[j].Findings {
				return out[i].Host < out[j].Host
			}
			return out[i].Findings > out[j].Findings
		}
		return left > right
	})

	if len(out) > 12 {
		out = out[:12]
	}

	return out
}

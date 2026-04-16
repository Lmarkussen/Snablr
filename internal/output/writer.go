package output

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/internal/ui"
)

const timeFormat = "2006-01-02 15:04:05 MST"

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type MetricsAware interface {
	SetMetricsSnapshot(metrics.Snapshot)
}

type BaselineAware interface {
	SetBaselineFindings([]scanner.Finding)
}

type validationManifestAware interface {
	SetValidationManifest(string)
}

type summaryCollector struct {
	mu sync.Mutex

	startedAt    time.Time
	endedAt      time.Time
	hosts        map[string]struct{}
	shares       map[string]struct{}
	filesScanned int
	skippedFiles int
	readErrors   int
	matchesFound int
}

type summarySnapshot struct {
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	HostsScanned  int       `json:"hosts_scanned"`
	SharesScanned int       `json:"shares_scanned"`
	FilesScanned  int       `json:"files_scanned"`
	MatchesFound  int       `json:"matches_found"`
	SkippedFiles  int       `json:"skipped_files"`
	ReadErrors    int       `json:"read_errors"`
}

type categorySummary struct {
	Category            string `json:"category"`
	Findings            int    `json:"findings"`
	Critical            int    `json:"critical"`
	High                int    `json:"high"`
	Medium              int    `json:"medium"`
	Low                 int    `json:"low"`
	HighestSeverity     string `json:"highest_severity"`
	RemediationGuidance string `json:"remediation_guidance"`
}

func newSummaryCollector() *summaryCollector {
	return &summaryCollector{
		startedAt: time.Now().UTC(),
		hosts:     make(map[string]struct{}),
		shares:    make(map[string]struct{}),
	}
}

func (s *summaryCollector) RecordHost(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(host) != "" {
		s.hosts[host] = struct{}{}
	}
}

func (s *summaryCollector) RecordShare(host, share string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(host) == "" && strings.TrimSpace(share) == "" {
		return
	}
	key := host + "::" + share
	s.shares[key] = struct{}{}
}

func (s *summaryCollector) RecordFile(meta scanner.FileMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filesScanned++
}

func (s *summaryCollector) RecordSkip(meta scanner.FileMetadata, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.skippedFiles++
}

func (s *summaryCollector) RecordReadError(meta scanner.FileMetadata, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readErrors++
}

func (s *summaryCollector) RecordFinding(f scanner.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matchesFound++
}

func (s *summaryCollector) Snapshot() summarySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endedAt.IsZero() {
		s.endedAt = time.Now().UTC()
	}
	return summarySnapshot{
		StartedAt:     s.startedAt,
		EndedAt:       s.endedAt,
		HostsScanned:  len(s.hosts),
		SharesScanned: len(s.shares),
		FilesScanned:  s.filesScanned,
		MatchesFound:  s.matchesFound,
		SkippedFiles:  s.skippedFiles,
		ReadErrors:    s.readErrors,
	}
}

func (s *summaryCollector) LiveSnapshot() summarySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return summarySnapshot{
		StartedAt:     s.startedAt,
		EndedAt:       s.endedAt,
		HostsScanned:  len(s.hosts),
		SharesScanned: len(s.shares),
		FilesScanned:  s.filesScanned,
		MatchesFound:  s.matchesFound,
		SkippedFiles:  s.skippedFiles,
		ReadErrors:    s.readErrors,
	}
}

func NewWriter(cfg config.OutputConfig) (scanner.FindingSink, error) {
	sinks := make([]scanner.FindingSink, 0, 5)
	selection, err := config.ParseOutputFormat(cfg.Format)
	if err != nil {
		return nil, err
	}
	liveMode := determineLiveSinkMode(cfg.Format, cfg.NoTUI, ui.ShouldShowProgress(cfg.Format))

	switch liveMode {
	case liveSinkTUI:
		tuiWriter, err := NewTUIWriter(os.Stdout, nopCloser{})
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, tuiWriter)
	case liveSinkConsole:
		sinks = append(sinks, NewConsoleWriter(os.Stdout, nopCloser{}))
	}

	if selection.JSON {
		file, err := createOutputFile(cfg.JSONOut)
		if err != nil {
			_ = closeSinks(sinks)
			return nil, fmt.Errorf("create json output file %s: %w", cfg.JSONOut, err)
		}
		jsonWriter := NewJSONWriter(file, file, cfg.Pretty)
		jsonWriter.SetBackupArtifactInventoryEnabled(cfg.ReportBackupArtifacts)
		sinks = append(sinks, jsonWriter)
	}

	if selection.HTML {
		file, err := createOutputFile(cfg.HTMLOut)
		if err != nil {
			_ = closeSinks(sinks)
			return nil, fmt.Errorf("create html output file %s: %w", cfg.HTMLOut, err)
		}
		htmlWriter, err := NewHTMLWriter(file, file)
		if err != nil {
			_ = file.Close()
			_ = closeSinks(sinks)
			return nil, err
		}
		htmlWriter.SetBackupArtifactInventoryEnabled(cfg.ReportBackupArtifacts)
		sinks = append(sinks, htmlWriter)
	}

	if strings.TrimSpace(cfg.CSVOut) != "" {
		csvFile, err := createOutputFile(cfg.CSVOut)
		if err != nil {
			_ = closeSinks(sinks)
			return nil, fmt.Errorf("create csv output file %s: %w", cfg.CSVOut, err)
		}
		sinks = append(sinks, NewCSVWriter(csvFile, csvFile))
	}

	if strings.TrimSpace(cfg.MDOut) != "" {
		mdFile, err := createOutputFile(cfg.MDOut)
		if err != nil {
			_ = closeSinks(sinks)
			return nil, fmt.Errorf("create markdown output file %s: %w", cfg.MDOut, err)
		}
		sinks = append(sinks, NewMarkdownWriter(mdFile, mdFile))
	}

	if strings.TrimSpace(cfg.CredsOut) != "" {
		credsFile, err := createOutputFile(cfg.CredsOut)
		if err != nil {
			_ = closeSinks(sinks)
			return nil, fmt.Errorf("create credential export file %s: %w", cfg.CredsOut, err)
		}
		sinks = append(sinks, NewCredsWriter(credsFile, credsFile))
	}

	if len(sinks) == 1 {
		return sinks[0], nil
	}
	return &MultiWriter{sinks: sinks}, nil
}

type MultiWriter struct {
	mu    sync.Mutex
	sinks []scanner.FindingSink
}

func (m *MultiWriter) WriteFinding(f scanner.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sink := range m.sinks {
		if err := sink.WriteFinding(f); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiWriter) RecordHost(host string) {
	m.broadcast(func(observer scanner.ScanObserver) { observer.RecordHost(host) })
}

func (m *MultiWriter) RecordShare(host, share string) {
	m.broadcast(func(observer scanner.ScanObserver) { observer.RecordShare(host, share) })
}

func (m *MultiWriter) RecordFile(meta scanner.FileMetadata) {
	m.broadcast(func(observer scanner.ScanObserver) { observer.RecordFile(meta) })
}

func (m *MultiWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	m.broadcast(func(observer scanner.ScanObserver) { observer.RecordSkip(meta, reason) })
}

func (m *MultiWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	m.broadcast(func(observer scanner.ScanObserver) { observer.RecordReadError(meta, err) })
}

func (m *MultiWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return closeSinks(m.sinks)
}

func (m *MultiWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	m.broadcastMetrics(func(aware MetricsAware) { aware.SetMetricsSnapshot(snapshot) })
}

func (m *MultiWriter) SetBaselineFindings(findings []scanner.Finding) {
	m.broadcastBaseline(func(aware BaselineAware) { aware.SetBaselineFindings(findings) })
}

func (m *MultiWriter) SetBaselinePerformance(summary *diff.PerformanceSummary) {
	m.broadcastBaselinePerformance(func(aware BaselinePerformanceAware) { aware.SetBaselinePerformance(summary) })
}

func (m *MultiWriter) SetValidationManifest(path string) {
	m.broadcastValidation(func(aware validationManifestAware) { aware.SetValidationManifest(path) })
}

func (m *MultiWriter) SetSuppressionSummary(summary *suppressionSummary) {
	m.broadcastSuppression(func(aware SuppressionSummaryAware) { aware.SetSuppressionSummary(summary) })
}

func (m *MultiWriter) SetScanProfile(profile string) {
	m.broadcastProfile(func(aware ScanProfileAware) { aware.SetScanProfile(profile) })
}

func (m *MultiWriter) SetValidationMode(enabled bool) {
	m.broadcastValidationMode(func(aware ValidationModeAware) { aware.SetValidationMode(enabled) })
}

func (m *MultiWriter) SetTargetTotal(total int) {
	m.broadcastLiveProgress(func(aware LiveProgressAware) { aware.SetTargetTotal(total) })
}

func (m *MultiWriter) SetCurrentHost(host string) {
	m.broadcastLiveProgress(func(aware LiveProgressAware) { aware.SetCurrentHost(host) })
}

func (m *MultiWriter) MarkTargetProcessed() {
	m.broadcastLiveProgress(func(aware LiveProgressAware) { aware.MarkTargetProcessed() })
}

func (m *MultiWriter) SetStatus(status string) {
	m.broadcastLiveProgress(func(aware LiveProgressAware) { aware.SetStatus(status) })
}

func (m *MultiWriter) SetCancelFunc(cancel context.CancelFunc) {
	m.broadcastCancel(func(aware ScanCancelAware) { aware.SetCancelFunc(cancel) })
}

func (m *MultiWriter) WasCanceledByUser() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(ScanCancelAware)
		if !ok {
			continue
		}
		if aware.WasCanceledByUser() {
			return true
		}
	}
	return false
}

func (m *MultiWriter) RecordSuppressedFinding(event scanner.SuppressedFinding) {
	m.broadcastValidationObserver(func(observer scanner.ValidationObserver) { observer.RecordSuppressedFinding(event) })
}

func (m *MultiWriter) RecordVisibleFinding(finding scanner.Finding) {
	m.broadcastValidationObserver(func(observer scanner.ValidationObserver) { observer.RecordVisibleFinding(finding) })
}

func (m *MultiWriter) RecordDowngradedFinding(finding scanner.Finding) {
	m.broadcastValidationObserver(func(observer scanner.ValidationObserver) { observer.RecordDowngradedFinding(finding) })
}

func (m *MultiWriter) broadcast(fn func(scanner.ScanObserver)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		observer, ok := sink.(scanner.ScanObserver)
		if !ok {
			continue
		}
		fn(observer)
	}
}

func (m *MultiWriter) broadcastMetrics(fn func(MetricsAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(MetricsAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastBaseline(fn func(BaselineAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(BaselineAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastBaselinePerformance(fn func(BaselinePerformanceAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(BaselinePerformanceAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastValidation(fn func(validationManifestAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(validationManifestAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastSuppression(fn func(SuppressionSummaryAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(SuppressionSummaryAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastProfile(fn func(ScanProfileAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(ScanProfileAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastValidationMode(fn func(ValidationModeAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(ValidationModeAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastLiveProgress(fn func(LiveProgressAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(LiveProgressAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastCancel(fn func(ScanCancelAware)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		aware, ok := sink.(ScanCancelAware)
		if !ok {
			continue
		}
		fn(aware)
	}
}

func (m *MultiWriter) broadcastValidationObserver(fn func(scanner.ValidationObserver)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sink := range m.sinks {
		observer, ok := sink.(scanner.ValidationObserver)
		if !ok {
			continue
		}
		fn(observer)
	}
}

func closeSinks(sinks []scanner.FindingSink) error {
	var errs []error
	for i := len(sinks) - 1; i >= 0; i-- {
		sink := sinks[i]
		if sink == nil {
			continue
		}
		if err := sink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func createOutputFile(path string) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("output path cannot be empty")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
}

func uncPath(f scanner.Finding) string {
	path := strings.ReplaceAll(f.FilePath, "/", `\`)
	if f.Host == "" && f.Share == "" {
		return path
	}
	if path != "" && !strings.HasPrefix(path, `\`) {
		path = `\` + path
	}
	return fmt.Sprintf(`\\%s\%s%s`, valueOrDash(f.Host), valueOrDash(f.Share), path)
}

func remoteFilePath(f scanner.Finding) string {
	switch {
	case strings.TrimSpace(f.ArchivePath) != "":
		return strings.TrimSpace(f.ArchivePath)
	case strings.TrimSpace(f.DatabaseFilePath) != "":
		return strings.TrimSpace(f.DatabaseFilePath)
	default:
		path := strings.TrimSpace(f.FilePath)
		if idx := strings.Index(path, "!"); idx >= 0 {
			path = path[:idx]
		}
		if idx := strings.Index(path, "::"); idx >= 0 {
			path = path[:idx]
		}
		return path
	}
}

func downloadHref(f scanner.Finding) string {
	host := strings.TrimSpace(f.Host)
	share := strings.TrimSpace(f.Share)
	path := strings.TrimSpace(remoteFilePath(f))
	if host == "" || share == "" || path == "" {
		return ""
	}
	parts := []string{host, share}
	for _, part := range strings.Split(strings.ReplaceAll(path, `\`, "/"), "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parts = append(parts, url.PathEscape(part))
	}
	return "file://" + strings.Join(parts, "/")
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func tagsOrDash(tags []string) string {
	if len(tags) == 0 {
		return "-"
	}
	return strings.Join(tags, ", ")
}

func SetMetricsSnapshot(sink scanner.FindingSink, snapshot metrics.Snapshot) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(MetricsAware); ok {
		aware.SetMetricsSnapshot(snapshot)
	}
}

func SetBaselineFindings(sink scanner.FindingSink, findings []scanner.Finding) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(BaselineAware); ok {
		aware.SetBaselineFindings(findings)
	}
}

func SetBaselineReport(sink scanner.FindingSink, report diff.Report) {
	if sink == nil {
		return
	}
	SetBaselineFindings(sink, report.Findings)
	SetBaselinePerformance(sink, report.Performance)
}

func buildCategorySummaries(findings []scanner.Finding) []categorySummary {
	if len(findings) == 0 {
		return nil
	}

	buckets := make(map[string]*categorySummary)
	for _, finding := range findings {
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			category = "uncategorized"
		}

		summary, ok := buckets[category]
		if !ok {
			summary = &categorySummary{
				Category:            category,
				RemediationGuidance: remediationGuidanceForCategory(category),
			}
			buckets[category] = summary
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

	out := make([]categorySummary, 0, len(buckets))
	for _, summary := range buckets {
		if strings.TrimSpace(summary.HighestSeverity) == "" {
			summary.HighestSeverity = "unknown"
		}
		out = append(out, *summary)
	}

	sort.Slice(out, func(i, j int) bool {
		left := severityRank(out[i].HighestSeverity)
		right := severityRank(out[j].HighestSeverity)
		if left == right {
			if out[i].Findings == out[j].Findings {
				return out[i].Category < out[j].Category
			}
			return out[i].Findings > out[j].Findings
		}
		return left > right
	})

	return out
}

func remediationGuidanceForCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "credentials":
		return "Rotate exposed secrets, move credentials into a managed secret store, and restrict access to the affected files and shares."
	case "crypto":
		return "Review exposed key or certificate material, replace or protect sensitive keys as needed, and restrict share access."
	case "configuration":
		return "Remove embedded secrets from shared configuration files, store sensitive settings securely, and limit access to these files."
	case "deployment":
		return "Review unattended deployment files for embedded credentials, rotate affected accounts, and keep deployment artifacts out of broadly shared locations."
	case "archives":
		return "Review retention of backup and export files, remove stale copies from shared locations, and restrict access to retained archives."
	case "password-manager":
		return "Move password-manager artifacts to approved storage, review who can access them, and confirm appropriate protection and retention controls."
	case "business-data", "pii":
		return "Remove unnecessary sensitive exports from shared locations, apply retention controls, and restrict share permissions to only required users."
	case "infrastructure":
		return "Move infrastructure secrets into managed storage, review exposed pipeline or cloud configuration files, and restrict access to operational shares."
	case "database-access":
		return "Remove embedded database credentials from shared files, rotate exposed accounts or passwords, and store connection material in approved secret-management paths."
	case "database-artifacts":
		return "Review whether database artifacts belong on the share, relocate or remove unnecessary copies, and restrict access to retained database files."
	case "database-infrastructure":
		return "Review database client and network configuration artifacts, confirm they are expected, and restrict access to files that expose server or DSN details."
	case "active-directory":
		return "Review AD policy and administration files for embedded secrets, remove exposed sensitive values, and tighten share permissions."
	case "scripts":
		return "Review scripts for embedded secrets, move credentials to managed storage, and restrict access to administrative script locations."
	default:
		return "Review the matched files, remove unnecessary sensitive material from shared locations, and restrict access to the affected shares."
	}
}

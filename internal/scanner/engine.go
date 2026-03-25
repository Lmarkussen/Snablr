package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"snablr/internal/archiveinspect"
	"snablr/internal/awsinspect"
	"snablr/internal/backupinspect"
	"snablr/internal/browsercredinspect"
	"snablr/internal/dbinspect"
	"snablr/internal/keyinspect"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/internal/sqliteinspect"
	"snablr/internal/wiminspect"
	"snablr/internal/wincredinspect"
	"snablr/pkg/logx"
)

type Options struct {
	Workers          int
	MaxFileSizeBytes int64
	MaxReadBytes     int64
	SnippetBytes     int
	Archives         archiveinspect.Options
	WIM              wiminspect.Options
	SQLite           sqliteinspect.Options
	Recorder         metrics.Recorder
	ValidationMode   bool
}

type Engine struct {
	opts             Options
	manager          *rules.Manager
	sink             FindingSink
	log              *logx.Logger
	recorder         metrics.Recorder
	filenameScanner  FilenameScanner
	extensionScanner ExtensionScanner
	contentScanner   ContentScanner
	filenameRules    []rules.Rule
	extensionRules   []rules.Rule
	contentRules     []rules.Rule
	contentExtHints  map[string]struct{}
	archiveExtHints  map[string]struct{}
	hasGenericText   bool
	backupInspector  backupinspect.Inspector
	awsInspector     awsinspect.Inspector
	browserInspector browsercredinspect.Inspector
	dbInspector      dbinspect.Inspector
	keyInspector     keyinspect.Inspector
	sqliteInspector  sqliteinspect.Inspector
	wimInspector     wiminspect.Options
	winCredInspector wincredinspect.Inspector
	validationMode   bool
	validationSink   ValidationObserver
}

func NewEngine(opts Options, manager *rules.Manager, sink FindingSink, log *logx.Logger) *Engine {
	opts.Workers = ResolveWorkerCount(opts.Workers)
	if opts.SnippetBytes <= 0 {
		opts.SnippetBytes = 120
	}
	opts.Archives = resolveArchiveOptions(opts.Archives)
	if manager == nil {
		manager = &rules.Manager{}
	}
	filenameRules := manager.RulesByType(rules.RuleTypeFilename)
	extensionRules := manager.RulesByType(rules.RuleTypeExtension)
	contentRules := manager.RulesByType(rules.RuleTypeContent)
	contentExtHints, hasGenericText := buildContentRuleHints(contentRules)
	archiveExtHints := buildArchiveExtensionHints(contentExtHints)

	return &Engine{
		opts:             opts,
		manager:          manager,
		sink:             sink,
		log:              log,
		recorder:         opts.Recorder,
		filenameScanner:  FilenameScanner{},
		extensionScanner: ExtensionScanner{},
		contentScanner:   NewContentScanner(opts.SnippetBytes, opts.ValidationMode, validationObserverForSink(sink), log),
		filenameRules:    filenameRules,
		extensionRules:   extensionRules,
		contentRules:     contentRules,
		contentExtHints:  contentExtHints,
		archiveExtHints:  archiveExtHints,
		hasGenericText:   hasGenericText,
		backupInspector:  backupinspect.New(),
		awsInspector:     awsinspect.New(),
		browserInspector: browsercredinspect.New(),
		dbInspector:      dbinspect.New(),
		keyInspector:     keyinspect.New(),
		sqliteInspector:  sqliteinspect.New(opts.SQLite),
		wimInspector:     opts.WIM,
		winCredInspector: wincredinspect.New(),
		validationMode:   opts.ValidationMode,
		validationSink:   validationObserverForSink(sink),
	}
}

func (e *Engine) Evaluate(meta FileMetadata, content []byte) Evaluation {
	meta = meta.Normalized()
	if meta.IsDir {
		return Evaluation{
			Skipped:    true,
			SkipReason: "directories are not scanned as files",
		}
	}

	if e.shouldSkipByPath(meta) {
		return Evaluation{
			Skipped:    true,
			SkipReason: "matched skip rule",
		}
	}

	if shouldInspect, skipReason, isArchive := e.archiveDecision(meta); isArchive {
		if !shouldInspect {
			return Evaluation{
				Skipped:    true,
				SkipReason: skipReason,
			}
		}
		return e.evaluateArchive(meta, content)
	}
	if shouldInspect, skipReason, isWIM := e.wimDecision(meta); isWIM {
		if !shouldInspect {
			return Evaluation{
				Skipped:    true,
				SkipReason: skipReason,
			}
		}
		return e.evaluateWIM(meta, content)
	}
	if shouldInspect, skipReason, isSQLite := e.sqliteDecision(meta); isSQLite && !shouldInspect {
		return Evaluation{
			Skipped:    true,
			SkipReason: skipReason,
		}
	}

	if e.opts.MaxFileSizeBytes > 0 && meta.Size > e.opts.MaxFileSizeBytes {
		return Evaluation{
			Skipped:    true,
			SkipReason: fmt.Sprintf("file exceeds max size limit of %d bytes", e.opts.MaxFileSizeBytes),
		}
	}

	return e.evaluateStandard(meta, content, false)
}

func (e *Engine) recordValidationFindings(findings []Finding) {
	if !e.validationMode || e.validationSink == nil || len(findings) == 0 {
		return
	}
	for _, finding := range findings {
		e.validationSink.RecordVisibleFinding(finding)
		if finding.ConfidenceBreakdown.TriageAdjustment < 0 || finding.TriageClass == "config-only" || finding.TriageClass == "weak-review" {
			e.validationSink.RecordDowngradedFinding(finding)
			if e.log != nil {
				e.log.Infof("validation: downgraded finding for %s rule=%s triage=%s confidence=%s", finding.FilePath, finding.RuleID, finding.TriageClass, finding.Confidence)
			}
		}
	}
}

func (e *Engine) ValidationMode() bool {
	return e != nil && e.validationMode
}

func validationObserverForSink(sink FindingSink) ValidationObserver {
	if sink == nil {
		return nil
	}
	observer, _ := sink.(ValidationObserver)
	return observer
}

func (e *Engine) NeedsContent(meta FileMetadata) bool {
	meta = meta.Normalized()
	if meta.IsDir || e.shouldSkipByPath(meta) {
		return false
	}
	if shouldInspect, _, isArchive := e.archiveDecision(meta); isArchive {
		return shouldInspect
	}
	if shouldInspect, _, isWIM := e.wimDecision(meta); isWIM {
		return shouldInspect
	}
	if shouldInspect, _, isSQLite := e.sqliteDecision(meta); isSQLite {
		return shouldInspect
	}
	if e.opts.MaxFileSizeBytes > 0 && meta.Size > e.opts.MaxFileSizeBytes {
		return false
	}
	return e.shouldReadContent(meta, e.contentRules) ||
		e.awsInspector.NeedsContent(awsCandidate(meta)) ||
		e.dbInspector.NeedsContent(dbCandidate(meta)) ||
		e.keyInspector.NeedsContent(keyCandidate(meta)) ||
		e.sqliteInspector.NeedsContent(sqliteCandidate(meta)) ||
		e.winCredInspector.NeedsContent(winCredCandidate(meta))
}

func (e *Engine) evaluateStandard(meta FileMetadata, content []byte, forceContent bool) Evaluation {
	evaluation := Evaluation{}

	evaluation.Findings = append(evaluation.Findings, e.filenameScanner.Scan(e.filenameRules, meta)...)
	evaluation.Findings = append(evaluation.Findings, e.extensionScanner.Scan(e.extensionRules, meta)...)
	evaluation.Findings = append(evaluation.Findings, findingsFromBackupMatches(meta, e.backupInspector.InspectMetadata(backupCandidate(meta)))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromAWSMatches(meta, e.awsInspector.InspectMetadata(awsCandidate(meta)))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromBrowserCredMatches(meta, e.browserInspector.InspectMetadata(browserCredCandidate(meta)))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromDBMatches(meta, e.dbInspector.InspectMetadata(dbCandidate(meta)))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromWinCredMatches(meta, e.winCredInspector.InspectMetadata(winCredCandidate(meta)))...)

	evaluation.NeedContent = forceContent ||
		e.shouldReadContent(meta, e.contentRules) ||
		e.awsInspector.NeedsContent(awsCandidate(meta)) ||
		e.dbInspector.NeedsContent(dbCandidate(meta)) ||
		e.keyInspector.NeedsContent(keyCandidate(meta)) ||
		e.sqliteInspector.NeedsContent(sqliteCandidate(meta)) ||
		e.winCredInspector.NeedsContent(winCredCandidate(meta))
	if !evaluation.NeedContent || len(content) == 0 {
		evaluation.Findings = correlateFindings(meta, evaluation.Findings)
		evaluation.Findings = adjustAWSArtifactVisibility(evaluation.Findings)
		evaluation.Findings = adjustBrowserArtifactVisibility(evaluation.Findings)
		e.recordValidationFindings(evaluation.Findings)
		return evaluation
	}

	evaluation.ContentRead = true
	if e.opts.MaxReadBytes > 0 && int64(len(content)) > e.opts.MaxReadBytes {
		content = content[:e.opts.MaxReadBytes]
	}

	evaluation.Findings = append(evaluation.Findings, e.contentScanner.Scan(e.contentRules, meta, content)...)
	evaluation.Findings = append(evaluation.Findings, findingsFromAWSMatches(meta, e.awsInspector.InspectContent(awsCandidate(meta), content))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromDBMatches(meta, e.dbInspector.InspectContent(dbCandidate(meta), content))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromKeyMatches(meta, e.keyInspector.InspectContent(keyCandidate(meta), content))...)
	evaluation.Findings = append(evaluation.Findings, findingsFromSQLiteMatches(meta, e.sqliteInspector.InspectContent(sqliteCandidate(meta), content))...)
	evaluation.Findings = correlateFindings(meta, evaluation.Findings)
	evaluation.Findings = adjustAWSArtifactVisibility(evaluation.Findings)
	evaluation.Findings = adjustBrowserArtifactVisibility(evaluation.Findings)
	e.recordValidationFindings(evaluation.Findings)
	return evaluation
}

func (e *Engine) evaluateArchive(meta FileMetadata, content []byte) Evaluation {
	evaluation := Evaluation{NeedContent: true}
	if len(content) == 0 {
		evaluation.Skipped = true
		evaluation.SkipReason = "archive content unavailable"
		return evaluation
	}
	evaluation.ContentRead = true

	archiveExt := archiveinspect.ResolveArchiveExtension(meta.Name, meta.FilePath, meta.Extension)
	var (
		result archiveinspect.Result
		err    error
	)
	switch archiveExt {
	case ".zip", ".docx", ".xlsx", ".pptx":
		result, err = archiveinspect.InspectZIP(content, archiveExt, e.opts.Archives, e.archiveExtHints)
	case ".tar", ".tar.gz", ".tgz":
		result, err = archiveinspect.InspectTAR(content, archiveExt, e.opts.Archives, e.archiveExtHints)
	default:
		evaluation.Skipped = true
		evaluation.SkipReason = fmt.Sprintf("unsupported archive type %q", archiveExt)
		return evaluation
	}
	if err != nil {
		evaluation.Skipped = true
		evaluation.SkipReason = fmt.Sprintf("archive inspection failed: %v", err)
		return evaluation
	}
	if !result.Inspected {
		evaluation.Skipped = true
		evaluation.SkipReason = result.SkipReason
		return evaluation
	}

	findings := make([]Finding, 0)
	for _, member := range result.Members {
		memberMeta := meta
		memberMeta.ArchivePath = meta.FilePath
		memberMeta.ArchiveMemberPath = member.Path
		memberMeta.ArchiveLocalInspect = result.InspectedLocally
		memberMeta.FilePath = archiveDisplayPath(meta.FilePath, member.Path)
		memberMeta.Name = member.Name
		memberMeta.Extension = member.Extension
		memberMeta.Size = member.Size

		memberEvaluation := e.evaluateStandard(memberMeta, member.Content, true)
		findings = append(findings, memberEvaluation.Findings...)
	}

	evaluation.Findings = findings
	return evaluation
}

func (e *Engine) evaluateWIM(meta FileMetadata, content []byte) Evaluation {
	evaluation := Evaluation{NeedContent: true}
	if len(content) == 0 {
		evaluation.Skipped = true
		evaluation.SkipReason = "wim content unavailable"
		return evaluation
	}
	evaluation.ContentRead = true

	result, err := wiminspect.Inspect(content, e.wimInspector)
	if err != nil {
		evaluation.Skipped = true
		evaluation.SkipReason = fmt.Sprintf("wim inspection failed: %v", err)
		return evaluation
	}
	if !result.Inspected {
		evaluation.Skipped = true
		evaluation.SkipReason = result.SkipReason
		return evaluation
	}

	findings := make([]Finding, 0)
	for _, member := range result.Members {
		memberMeta := meta
		memberMeta.ArchivePath = meta.FilePath
		memberMeta.ArchiveMemberPath = member.Path
		memberMeta.ArchiveLocalInspect = result.InspectedLocally
		memberMeta.FilePath = archiveDisplayPath(meta.FilePath, member.Path)
		memberMeta.Name = member.Name
		memberMeta.Extension = member.Extension
		memberMeta.Size = member.Size

		memberEvaluation := e.evaluateStandard(memberMeta, member.Content, member.ContentRead)
		findings = append(findings, memberEvaluation.Findings...)
	}

	evaluation.Findings = findings
	return evaluation
}

func (e *Engine) archiveDecision(meta FileMetadata) (bool, string, bool) {
	normalized := archiveinspect.ResolveArchiveExtension(meta.Name, meta.FilePath, meta.Extension)
	switch normalized {
	case ".zip", ".docx", ".xlsx", ".pptx", ".tar", ".tar.gz", ".tgz":
	default:
		return false, "", false
	}
	shouldInspect, reason := archiveinspect.ShouldInspect(archiveinspect.Candidate{
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}, e.opts.Archives)
	return shouldInspect, reason, true
}

func (e *Engine) wimDecision(meta FileMetadata) (bool, string, bool) {
	if normalizeExtension(meta.Extension) != ".wim" {
		return false, "", false
	}
	shouldInspect, reason := wiminspect.ShouldInspect(wiminspect.Candidate{
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	}, e.wimInspector)
	return shouldInspect, reason, true
}

func (e *Engine) sqliteDecision(meta FileMetadata) (bool, string, bool) {
	switch normalizeExtension(meta.Extension) {
	case ".sqlite", ".sqlite3", ".db", ".db3":
		shouldInspect, reason := sqliteinspect.ShouldInspect(sqliteCandidate(meta), e.opts.SQLite)
		return shouldInspect, reason, true
	default:
		return false, "", false
	}
}

func (e *Engine) shouldReadContent(meta FileMetadata, contentRules []rules.Rule) bool {
	if e.opts.MaxReadBytes > 0 && meta.Size > e.opts.MaxReadBytes {
		return false
	}
	if len(contentRules) == 0 {
		return false
	}
	if !e.hasGenericText {
		if _, ok := e.contentExtHints[normalizeExtension(meta.Extension)]; !ok {
			return false
		}
	}
	return e.contentScanner.NeedsContent(contentRules, meta)
}

func (e *Engine) shouldSkipByPath(meta FileMetadata) bool {
	ext := meta.Extension
	if resolved := archiveinspect.ResolveArchiveExtension(meta.Name, meta.FilePath, meta.Extension); resolved != "" {
		switch resolved {
		case ".zip", ".docx", ".xlsx", ".pptx", ".tar", ".tar.gz", ".tgz":
			ext = resolved
		}
	}
	candidate := rules.Candidate{
		Path:      meta.FilePath,
		Name:      meta.Name,
		Extension: ext,
		Size:      meta.Size,
		IsDir:     meta.IsDir,
	}
	skip, _ := e.manager.ShouldExclude(candidate)
	return skip
}

func (e *Engine) Run(ctx context.Context, targets []string) error {
	bufferSize := e.opts.Workers * 2
	if bufferSize <= 0 {
		bufferSize = 2
	}

	jobs := make(chan Job, bufferSize)
	errCh := make(chan error, 1)
	go func() {
		errCh <- NewWorkerPool(e, e.sink, e.log, e.recorder, e.opts.Workers).Scan(ctx, jobs)
	}()

	var enqueueErr error
	for _, target := range targets {
		if err := e.enqueueTarget(ctx, jobs, target); err != nil {
			enqueueErr = err
			break
		}
	}

	close(jobs)
	workerErr := <-errCh

	if enqueueErr != nil {
		return enqueueErr
	}
	if workerErr != nil {
		return workerErr
	}
	if e.sink != nil {
		return e.sink.Close()
	}
	return nil
}

func (e *Engine) enqueueTarget(ctx context.Context, jobs chan<- Job, target string) error {
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %s: %w", target, err)
	}
	if !info.IsDir() {
		meta := FileMetadata{
			FilePath:  target,
			Size:      info.Size(),
			IsDir:     false,
			Name:      info.Name(),
			Extension: filepath.Ext(info.Name()),
		}
		return submitJob(ctx, jobs, Job{
			Metadata: meta,
			LoadContent: func(_ context.Context, _ FileMetadata) ([]byte, error) {
				return readLimited(target, e.opts.MaxReadBytes)
			},
		})
	}

	return filepath.Walk(target, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if e.log != nil {
				e.log.Warnf("walk error for %s: %v", path, walkErr)
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if info.IsDir() {
			meta := FileMetadata{
				FilePath: path,
				Size:     info.Size(),
				IsDir:    true,
				Name:     info.Name(),
			}.Normalized()
			if e.shouldSkipByPath(meta) {
				return filepath.SkipDir
			}
			return nil
		}

		meta := FileMetadata{
			FilePath:  path,
			Size:      info.Size(),
			IsDir:     false,
			Name:      info.Name(),
			Extension: filepath.Ext(info.Name()),
		}
		return submitJob(ctx, jobs, Job{
			Metadata: meta,
			LoadContent: func(_ context.Context, _ FileMetadata) ([]byte, error) {
				return readLimited(path, e.opts.MaxReadBytes)
			},
		})
	})
}

func submitJob(ctx context.Context, jobs chan<- Job, job Job) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case jobs <- job:
		return nil
	}
}

func readLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if maxBytes <= 0 {
		return io.ReadAll(f)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

var regexCache sync.Map

func compiledPattern(rule rules.Rule) (*regexp.Regexp, error) {
	key := rule.ID + ":" + rule.Pattern
	if cached, ok := regexCache.Load(key); ok {
		return cached.(*regexp.Regexp), nil
	}

	expr := rule.Pattern
	if !rule.CaseSensitive {
		expr = "(?i)" + expr
	}

	compiled, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	regexCache.Store(key, compiled)
	return compiled, nil
}

func firstMatch(rule rules.Rule, input string) (string, bool) {
	rx, err := compiledPattern(rule)
	if err != nil {
		return "", false
	}

	match := rx.FindString(input)
	if match == "" {
		return "", false
	}
	return match, true
}

func ruleMatchesMetadata(rule rules.Rule, meta FileMetadata) bool {
	if rule.MaxFileSize > 0 && meta.Size > rule.MaxFileSize {
		return false
	}
	if len(rule.FileExtensions) > 0 && !extensionAllowed(meta.Extension, rule.FileExtensions) {
		return false
	}
	if len(rule.IncludePaths) > 0 && !containsPath(meta.FilePath, rule.IncludePaths) {
		return false
	}
	if len(rule.ExcludePaths) > 0 && containsPath(meta.FilePath, rule.ExcludePaths) {
		return false
	}
	return true
}

func extensionAllowed(ext string, allowed []string) bool {
	normalized := normalizeExtension(ext)
	for _, candidate := range allowed {
		if normalized == normalizeExtension(candidate) {
			return true
		}
	}
	return false
}

func containsPath(path string, patterns []string) bool {
	path = rules.NormalizePath(path)
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if match, _ := regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), path); match {
			return true
		}
	}
	return false
}

func buildContentRuleHints(ruleSet []rules.Rule) (map[string]struct{}, bool) {
	hints := make(map[string]struct{})
	hasGeneric := false
	for _, rule := range ruleSet {
		if rule.Action == rules.ActionSkip {
			continue
		}
		if len(rule.FileExtensions) == 0 {
			hasGeneric = true
			continue
		}
		for _, ext := range rule.FileExtensions {
			normalized := normalizeExtension(ext)
			if normalized == "" {
				continue
			}
			hints[normalized] = struct{}{}
		}
	}
	return hints, hasGeneric
}

func buildArchiveExtensionHints(contentHints map[string]struct{}) map[string]struct{} {
	hints := map[string]struct{}{
		".txt":        {},
		".ini":        {},
		".conf":       {},
		".config":     {},
		".xml":        {},
		".json":       {},
		".yaml":       {},
		".yml":        {},
		".csv":        {},
		".log":        {},
		".ps1":        {},
		".bat":        {},
		".cmd":        {},
		".vbs":        {},
		".sh":         {},
		".bash":       {},
		".zsh":        {},
		".py":         {},
		".rb":         {},
		".php":        {},
		".pl":         {},
		".js":         {},
		".ts":         {},
		".cs":         {},
		".vb":         {},
		".java":       {},
		".go":         {},
		".sql":        {},
		".reg":        {},
		".env":        {},
		".md":         {},
		".dsn":        {},
		".udl":        {},
		".ora":        {},
		".properties": {},
		".toml":       {},
		".ovpn":       {},
		".ppk":        {},
	}
	for ext := range contentHints {
		hints[normalizeExtension(ext)] = struct{}{}
	}
	return hints
}

func archiveDisplayPath(outerPath, memberPath string) string {
	return rules.NormalizePath(strings.TrimSpace(outerPath) + "!" + strings.TrimSpace(memberPath))
}

func normalizeExtension(ext string) string {
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.ToLower(ext)
}

func resolveArchiveOptions(opts archiveinspect.Options) archiveinspect.Options {
	if !opts.Enabled && !opts.AllowLargeZIPs && !opts.AllowLargeTARs && opts.AutoZIPMaxSize == 0 && opts.MaxZIPSize == 0 && opts.AutoTARMaxSize == 0 && opts.MaxTARSize == 0 && opts.MaxMembers == 0 && opts.MaxMemberBytes == 0 && opts.MaxTotalUncompressed == 0 && !opts.InspectExtensionlessText {
		return archiveinspect.Options{
			Enabled:                  true,
			AutoZIPMaxSize:           10 * 1024 * 1024,
			AllowLargeZIPs:           false,
			MaxZIPSize:               10 * 1024 * 1024,
			AutoTARMaxSize:           10 * 1024 * 1024,
			AllowLargeTARs:           false,
			MaxTARSize:               10 * 1024 * 1024,
			MaxMembers:               64,
			MaxMemberBytes:           512 * 1024,
			MaxTotalUncompressed:     4 * 1024 * 1024,
			InspectExtensionlessText: true,
		}
	}
	if opts.AutoZIPMaxSize <= 0 {
		opts.AutoZIPMaxSize = 10 * 1024 * 1024
	}
	if opts.MaxZIPSize <= 0 {
		opts.MaxZIPSize = opts.AutoZIPMaxSize
	}
	if opts.AutoTARMaxSize <= 0 {
		opts.AutoTARMaxSize = 10 * 1024 * 1024
	}
	if opts.MaxTARSize <= 0 {
		opts.MaxTARSize = opts.AutoTARMaxSize
	}
	if opts.MaxMembers <= 0 {
		opts.MaxMembers = 64
	}
	if opts.MaxMemberBytes <= 0 {
		opts.MaxMemberBytes = 512 * 1024
	}
	if opts.MaxTotalUncompressed <= 0 {
		opts.MaxTotalUncompressed = 4 * 1024 * 1024
	}
	return opts
}

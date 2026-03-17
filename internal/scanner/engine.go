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

	"snablr/internal/dbinspect"
	"snablr/internal/metrics"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

type Options struct {
	Workers          int
	MaxFileSizeBytes int64
	MaxReadBytes     int64
	SnippetBytes     int
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
	hasGenericText   bool
	dbInspector      dbinspect.Inspector
	validationMode   bool
	validationSink   ValidationObserver
}

func NewEngine(opts Options, manager *rules.Manager, sink FindingSink, log *logx.Logger) *Engine {
	opts.Workers = ResolveWorkerCount(opts.Workers)
	if opts.SnippetBytes <= 0 {
		opts.SnippetBytes = 120
	}
	if manager == nil {
		manager = &rules.Manager{}
	}
	filenameRules := manager.RulesByType(rules.RuleTypeFilename)
	extensionRules := manager.RulesByType(rules.RuleTypeExtension)
	contentRules := manager.RulesByType(rules.RuleTypeContent)
	contentExtHints, hasGenericText := buildContentRuleHints(contentRules)

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
		hasGenericText:   hasGenericText,
		dbInspector:      dbinspect.New(),
		validationMode:   opts.ValidationMode,
		validationSink:   validationObserverForSink(sink),
	}
}

func (e *Engine) Evaluate(meta FileMetadata, content []byte) Evaluation {
	meta = meta.Normalized()
	evaluation := Evaluation{}

	if meta.IsDir {
		evaluation.Skipped = true
		evaluation.SkipReason = "directories are not scanned as files"
		return evaluation
	}

	if e.shouldSkipByPath(meta) {
		evaluation.Skipped = true
		evaluation.SkipReason = "matched skip rule"
		return evaluation
	}

	if e.opts.MaxFileSizeBytes > 0 && meta.Size > e.opts.MaxFileSizeBytes {
		evaluation.Skipped = true
		evaluation.SkipReason = fmt.Sprintf("file exceeds max size limit of %d bytes", e.opts.MaxFileSizeBytes)
		return evaluation
	}

	evaluation.Findings = append(evaluation.Findings, e.filenameScanner.Scan(e.filenameRules, meta)...)
	evaluation.Findings = append(evaluation.Findings, e.extensionScanner.Scan(e.extensionRules, meta)...)
	evaluation.Findings = append(evaluation.Findings, findingsFromDBMatches(meta, e.dbInspector.InspectMetadata(dbCandidate(meta)))...)

	evaluation.NeedContent = e.shouldReadContent(meta, e.contentRules) || e.dbInspector.NeedsContent(dbCandidate(meta))
	if !evaluation.NeedContent || len(content) == 0 {
		evaluation.Findings = correlateFindings(meta, evaluation.Findings)
		e.recordValidationFindings(evaluation.Findings)
		return evaluation
	}

	evaluation.ContentRead = true
	if e.opts.MaxReadBytes > 0 && int64(len(content)) > e.opts.MaxReadBytes {
		content = content[:e.opts.MaxReadBytes]
	}

	evaluation.Findings = append(evaluation.Findings, e.contentScanner.Scan(e.contentRules, meta, content)...)
	evaluation.Findings = append(evaluation.Findings, findingsFromDBMatches(meta, e.dbInspector.InspectContent(dbCandidate(meta), content))...)
	evaluation.Findings = correlateFindings(meta, evaluation.Findings)
	e.recordValidationFindings(evaluation.Findings)
	return evaluation
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
	if e.opts.MaxFileSizeBytes > 0 && meta.Size > e.opts.MaxFileSizeBytes {
		return false
	}
	return e.shouldReadContent(meta, e.contentRules) || e.dbInspector.NeedsContent(dbCandidate(meta))
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
	candidate := rules.Candidate{
		Path:      meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
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

func normalizeExtension(ext string) string {
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.ToLower(ext)
}

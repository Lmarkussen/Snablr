package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"snablr/internal/archiveinspect"
	"snablr/internal/artifact"
	"snablr/internal/artifactbundle"
	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/output"
	"snablr/internal/planner"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/sqliteinspect"
	"snablr/internal/state"
	"snablr/internal/store"
	"snablr/internal/ui"
	"snablr/internal/version"
	"snablr/internal/wiminspect"
	"snablr/pkg/logx"
)

const sharePlanningBatchSize = 2048

type bundleCandidate struct {
	remote   smb.RemoteFile
	filePlan planner.PlannedTarget
}

type scanClient interface {
	SetMaxReadSize(int64)
	Close() error
	ConnectWithAuth(string, smb.Auth) error
	ListShares() ([]smb.ShareInfo, error)
	WalkShareWithOptions(string, smb.WalkOptions, func(smb.RemoteFile) error) error
	ReadFile(string, string) ([]byte, error)
}

func bundleKind(remote smb.RemoteFile) (artifact.Kind, bool) {
	kind, ok := artifact.KindForPath(remote.Path)
	return kind, ok && (kind == artifact.KindSAM || kind == artifact.KindSYSTEM || kind == artifact.KindSECURITY || kind == artifact.KindNTDS)
}

var (
	runScanPreflightFunc = runScanPreflight
	newOutputWriterFunc  = output.NewWriter
	resolveTargetsFunc   = discovery.Resolve
	newScanClientFunc    = func() scanClient { return smb.NewClient() }
)

func RunScan(ctx context.Context, opts ScanOptions) (err error) {
	cfg, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	applyScanOverrides(&cfg, opts)
	if err := validateScanConfig(cfg); err != nil {
		return err
	}
	if _, err := config.ParseOutputFormat(cfg.Output.Format); err != nil {
		return err
	}
	if opts.ListShares {
		return runListShares(ctx, cfg, logger)
	}
	interactiveTerminal := ui.ShouldShowProgress(cfg.Output.Format)
	useInteractiveTUI := !cfg.Output.NoTUI && interactiveTerminal
	if err := runScanPreflightFunc(ctx, cfg, useInteractiveTUI, logger); err != nil {
		return err
	}
	logPersistenceNotice(cfg, logger)
	cfg.Scan.WorkerCount = scanner.ResolveWorkerCount(cfg.Scan.WorkerCount)
	logger.Infof("using %d file scan worker(s)", cfg.Scan.WorkerCount)

	scanCtx := ctx
	var timeoutCancel context.CancelFunc
	maxScanDuration, err := cfg.Scan.MaxScanDuration()
	if err != nil {
		return err
	}
	if maxScanDuration > 0 {
		scanCtx, timeoutCancel = context.WithTimeout(ctx, maxScanDuration)
		defer timeoutCancel()
	}
	scanCtx, scanCancel := context.WithCancel(scanCtx)
	defer scanCancel()
	operatorInterrupted := false

	manager, err := loadRuleManager(cfg, logger)
	if err != nil {
		return err
	}
	if issues := manager.Validate(); len(issues) > 0 {
		for _, issue := range issues {
			logger.Warnf("%s", issue.Error())
		}
		return fmt.Errorf("rule validation failed with %d issue(s)", len(issues))
	}
	semantics := scanSemanticsFingerprint(cfg, manager)

	var shadow *store.SQLiteStore
	var sqliteResume *store.ResumeState
	sqliteAuthority := true
	if sqliteAuthority {
		sqlitePath := sqliteStatePath(cfg)
		var resumeState store.ResumeState
		var resumeErr error
		if cfg.Scan.Resume {
			shadow, resumeState, resumeErr = store.OpenForResume(sqlitePath, store.ResumeOptions{ExpectedSemantics: semantics, MaterializeFiles: false})
			if resumeErr != nil {
				return fmt.Errorf("open authoritative SQLite resume state: %w", resumeErr)
			}
			sqliteResume = &resumeState
		} else if !cfg.Scan.ForceRescan {
			var reused bool
			shadow, resumeState, reused, resumeErr = store.OpenLatestForReuse(sqlitePath, store.ResumeOptions{ExpectedSemantics: semantics, MaterializeFiles: false})
			if resumeErr != nil {
				return fmt.Errorf("open compatible SQLite reuse state: %w", resumeErr)
			}
			if reused {
				sqliteResume = &resumeState
				logger.Infof("reusing compatible SQLite scan state %s", resumeState.ScanID)
			}
			if !reused {
				shadow, err = store.Open(sqlitePath, store.Options{Semantics: semantics, SnablrVersion: version.String()})
				if err != nil {
					return fmt.Errorf("open authoritative SQLite state: %w", err)
				}
			}
		} else {
			shadow, err = store.Open(sqlitePath, store.Options{Semantics: semantics, SnablrVersion: version.String()})
			if err != nil {
				return fmt.Errorf("open authoritative SQLite state: %w", err)
			}
		}
	}
	var authorityMonitorStop chan struct{}
	authorityFailure := func() error {
		if !sqliteAuthority || shadow == nil {
			return nil
		}
		if failure := shadow.Failure(); failure != nil {
			return fmt.Errorf("authoritative SQLite state failed: %w", failure)
		}
		return nil
	}
	if sqliteAuthority {
		authorityMonitorStop = make(chan struct{})
		go func() {
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			failed := false
			for {
				select {
				case <-ticker.C:
					if shadow.Failure() != nil && !failed {
						failed = true
						scanCancel()
					}
				case <-authorityMonitorStop:
					return
				}
			}
		}()
		defer func() {
			close(authorityMonitorStop)
		}()
	}

	var sink scanner.FindingSink
	recorder := metrics.NewCollector()
	totalTimer := recorder.StartPhase("total_scan")
	defer func() {
		totalTimer.Stop()
		if sink != nil {
			output.SetMetricsSnapshot(sink, recorder.Snapshot())
		}
	}()

	var stateManager *state.Manager
	if sqliteAuthority {
		semanticsMatch := true
		if sqliteResume != nil {
			semanticsMatch = sqliteResume.SemanticsMatch
		}
		reader := sqliteResumeReader{shadow: shadow, semanticsMatch: semanticsMatch, expectedSemantics: semantics}
		stateManager = state.NewManagerFromSQLiteReader(reader, 10*time.Second)
	}
	if stateManager != nil {
		stateManager.Start(scanCtx)
		defer stateManager.Close()
	}

	incrementalEnabled := sqliteAuthority
	var inventory *state.InventoryManager
	if incrementalEnabled {
		if sqliteAuthority {
			semanticsMatch := true
			if sqliteResume != nil {
				semanticsMatch = sqliteResume.SemanticsMatch
			}
			inventory = state.NewInventoryManagerFromSQLiteReader(sqliteResumeReader{shadow: shadow, semanticsMatch: semanticsMatch, expectedSemantics: semantics}, 10*time.Second)
		}
		if inventory != nil {
			inventory.Start(scanCtx)
			defer func() {
				_ = inventory.Close()
			}()
		}
	}
	credentialContextID := state.CredentialContextID(cfg.Scan.SMBAuth, cfg.Scan.Username, cfg.Scan.Domain)
	if shadow != nil {
		if stateManager != nil {
			stateManager.AttachStore(shadow, shadow.ScanID())
		}
		if inventory != nil {
			inventory.AttachStore(shadow, shadow.ScanID())
		}
		defer func() {
			status := store.StatusCompleted
			if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
				status = store.StatusTimedOut
			} else if operatorInterrupted || errors.Is(scanCtx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink) {
				status = store.StatusInterrupted
			}
			if shadow.Failure() != nil || (err != nil && status != store.StatusInterrupted) {
				status = store.StatusFailed
			}
			if statusErr := shadow.SetScanStatus(status, time.Now().UTC()); statusErr != nil && err == nil {
				err = fmt.Errorf("authoritative SQLite status update failed: %w", statusErr)
			}
			if closeErr := shadow.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("authoritative SQLite state close failed: %w", closeErr)
			}
		}()
	}

	bundles := artifactbundle.New(artifactbundle.Options{})
	defer func() { _ = bundles.Close() }()
	engine := scanner.NewEngine(scanner.Options{
		Workers:          cfg.Scan.WorkerCount,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     scanReadLimit(cfg),
		SnippetBytes:     120,
		Archives: archiveinspect.Options{
			Enabled:                  cfg.Archives.Enabled,
			AutoZIPMaxSize:           cfg.Archives.AutoZIPMaxSize,
			AllowLargeZIPs:           cfg.Archives.AllowLargeZIPs,
			MaxZIPSize:               cfg.Archives.MaxZIPSize,
			AutoTARMaxSize:           cfg.Archives.AutoTARMaxSize,
			AllowLargeTARs:           cfg.Archives.AllowLargeTARs,
			MaxTARSize:               cfg.Archives.MaxTARSize,
			MaxMembers:               cfg.Archives.MaxMembers,
			MaxMemberBytes:           cfg.Archives.MaxMemberBytes,
			MaxTotalUncompressed:     cfg.Archives.MaxTotalUncompressed,
			InspectExtensionlessText: cfg.Archives.InspectExtensionlessText,
		},
		WIM: wiminspect.Options{
			Enabled:            cfg.WIM.Enabled,
			AutoWIMMaxSize:     cfg.WIM.AutoWIMMaxSize,
			AllowLargeWIMs:     cfg.WIM.AllowLargeWIMs,
			MaxWIMSize:         cfg.WIM.MaxWIMSize,
			MaxMembers:         cfg.WIM.MaxMembers,
			MaxMemberBytes:     cfg.WIM.MaxMemberBytes,
			MaxTotalBytes:      cfg.WIM.MaxTotalBytes,
			MaxBinaryArtifacts: cfg.WIM.MaxBinaryArtifacts,
			MaxBinaryBytes:     cfg.WIM.MaxBinaryBytes,
			MaxSAMBytes:        cfg.WIM.MaxSAMBytes,
			MaxSYSTEMBytes:     cfg.WIM.MaxSYSTEMBytes,
			MaxSECURITYBytes:   cfg.WIM.MaxSECURITYBytes,
			MaxNTDSBytes:       cfg.WIM.MaxNTDSBytes,
			MaxImages:          cfg.WIM.MaxImages,
		},
		SQLite: sqliteinspect.Options{
			Enabled:            cfg.SQLite.Enabled,
			AutoDBMaxSize:      cfg.SQLite.AutoDBMaxSize,
			AllowLargeDBs:      cfg.SQLite.AllowLargeDBs,
			MaxDBSize:          cfg.SQLite.MaxDBSize,
			MaxTables:          cfg.SQLite.MaxTables,
			MaxRowsPerTable:    cfg.SQLite.MaxRowsPerTable,
			MaxCellBytes:       cfg.SQLite.MaxCellBytes,
			MaxTotalBytes:      cfg.SQLite.MaxTotalBytes,
			MaxInterestingCols: cfg.SQLite.MaxInterestingCols,
		},
		Recorder:          recorder,
		ValidationMode:    cfg.Scan.ValidationMode,
		BundleCoordinator: bundles,
		SAMMaxBytes:       cfg.WIM.MaxSAMBytes,
		SYSTEMMaxBytes:    cfg.WIM.MaxSYSTEMBytes,
		SECURITYMaxBytes:  cfg.WIM.MaxSECURITYBytes,
		NTDSMaxBytes:      cfg.WIM.MaxNTDSBytes,
	}, manager, sink, logger)

	resolvedTargets, err := resolveTargetsFunc(scanCtx, cfg.Scan, logger, recorder)
	if err != nil {
		if errors.Is(err, context.Canceled) && (errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink)) {
			operatorInterrupted = true
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Warnf("max scan time reached during target discovery")
			return nil
		}
		return err
	}
	if len(resolvedTargets.DiscoveredHosts) > 0 {
		logger.Infof("ldap discovery returned %d host(s)", len(resolvedTargets.DiscoveredHosts))
	}
	if len(resolvedTargets.DFSTargets) > 0 {
		logger.Infof("dfs discovery returned %d target(s)", len(resolvedTargets.DFSTargets))
	}
	logger.Infof("Targets loaded: %d", resolvedTargets.Stats.Loaded)
	logger.Infof("Unique targets: %d", resolvedTargets.Stats.Unique)
	logger.Infof("Reachable SMB hosts: %d", resolvedTargets.Stats.Reachable)
	logger.Infof("Skipped hosts: %d", resolvedTargets.Stats.Skipped)

	hostInputs := make([]planner.HostInput, 0, len(resolvedTargets.ReachableTargets))
	for _, target := range resolvedTargets.ReachableTargets {
		if strings.TrimSpace(target.Hostname) != "" {
			hostInputs = append(hostInputs, planner.HostInput{
				Host:   target.Hostname,
				Source: target.Source,
			})
			continue
		}
		if strings.TrimSpace(target.IP) != "" {
			hostInputs = append(hostInputs, planner.HostInput{
				Host:   target.IP,
				Source: target.Source,
			})
		}
	}
	if len(hostInputs) == 0 {
		return fmt.Errorf("no reachable SMB targets available after discovery and reachability checks; provide --targets, adjust discovery settings, or use --skip-reachability-check to inspect unreachable targets")
	}

	planningTimer := recorder.StartPhase("host_planning")
	plannedHosts := planner.PlanHosts(hostInputs)
	planningTimer.Stop()
	if len(plannedHosts) > 0 {
		logger.Infof("scan plan prepared for %d host(s); highest priority=%d (%s)", len(plannedHosts), plannedHosts[0].Priority, plannedHosts[0].Reason)
	}
	if err := writeScannedTargets(cfg.Output.ScannedTargetsOut, resolvedTargets, plannedHosts); err != nil {
		return err
	}

	if useInteractiveTUI {
		logger.Infof("startup complete; launching live TUI")
		logger.SetOutput(io.Discard)
	}

	sink, err = newOutputWriterFunc(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	sink = output.WrapWithSuppression(sink, cfg.Suppression)
	output.AttachSQLiteStore(sink, shadow)
	output.SetFindingsDatabasePath(sink, sqliteStatePath(cfg))
	if exporter, ok := sink.(scanner.SensitiveCredentialExporter); ok {
		engine.SetCredentialExporter(exporter)
	}
	if recorder, ok := sink.(scanner.CredentialCandidateSink); ok {
		engine.SetCredentialCandidateSink(recorder)
	}
	if sqliteResume != nil {
		if err := replaySQLiteState(sink, *sqliteResume); err != nil {
			return fmt.Errorf("rehydrate SQLite findings: %w", err)
		}
	}
	output.SetCancelFunc(sink, scanCancel)
	output.SetScanProfile(sink, strings.TrimSpace(cfg.Scan.Profile))
	defer func() {
		if sink == nil {
			return
		}
		output.SetMetricsSnapshot(sink, recorder.Snapshot())
		wasInterrupted := operatorInterrupted || errors.Is(scanCtx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink)
		if wasInterrupted {
			output.SetScanInterrupted(sink, "operator interruption")
		}
		if closeErr := sink.Close(); closeErr != nil {
			if logger != nil {
				logger.Errorf("output finalization failed: %v", closeErr)
			}
			if err == nil {
				err = closeErr
			}
		}
		if wasInterrupted && (err == nil || errors.Is(err, context.Canceled)) {
			err = &ExitError{Code: 130, Err: fmt.Errorf("scan interrupted by operator")}
		}
	}()
	defer func() {
		if inventory != nil {
			stats := inventory.Stats()
			recorder.SetIncrementalCounters(stats.Discovered, stats.Inspected, stats.SkippedUnchanged, stats.RescannedChanged, stats.Retried, stats.NewAccessibleKnown)
			logger.Infof("incremental: discovered=%d inspected=%d skipped_unchanged=%d rescanned_changed=%d retried=%d newly_accessible_known=%d", stats.Discovered, stats.Inspected, stats.SkippedUnchanged, stats.RescannedChanged, stats.Retried, stats.NewAccessibleKnown)
		}
		if sink != nil {
			output.SetMetricsSnapshot(sink, recorder.Snapshot())
		}
	}()

	if strings.TrimSpace(cfg.Scan.Baseline) != "" {
		baseline, err := diff.LoadJSON(cfg.Scan.Baseline)
		if err != nil {
			return fmt.Errorf("load baseline %s: %w", cfg.Scan.Baseline, err)
		}
		output.SetBaselineReport(sink, baseline)
		logger.Infof("loaded %d baseline finding(s) for diff reporting", len(baseline.Findings))
	}
	if strings.TrimSpace(cfg.Scan.SeedManifest) != "" {
		output.SetValidationManifest(sink, cfg.Scan.SeedManifest)
		logger.Infof("enabled seeded validation summary in reporting")
	}
	if cfg.Scan.ValidationMode {
		output.SetValidationMode(sink, true)
		logger.Infof("validation mode enabled")
	}

	var progress *ui.ProgressReporter
	if output.SupportsLiveProgress(sink) {
		output.SetTargetTotal(sink, len(plannedHosts))
	} else if interactiveTerminal {
		progress = ui.NewProgressReporter(os.Stderr, recorder, 3*time.Second)
		progress.SetTargetTotal(len(plannedHosts))
		progress.Start(scanCtx)
		defer progress.Close()
	}

	var errs []error
	timedOut := false
	scanTimer := recorder.StartPhase("host_scanning")
	for _, target := range plannedHosts {
		if failure := authorityFailure(); failure != nil {
			return failure
		}
		if err := scanCtx.Err(); err != nil {
			if failure := authorityFailure(); failure != nil {
				return failure
			}
			if errors.Is(err, context.Canceled) && (errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink)) {
				operatorInterrupted = true
				return nil
			}
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				break
			}
			return err
		}
		if !cfg.Scan.ForceRescan && (sqliteAuthority || !incrementalEnabled) && stateManager != nil && stateManager.ShouldSkipHost(target.Host) {
			logger.Infof("resume: skipping completed host %s", target.Host)
			output.MarkTargetProcessed(sink)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		output.SetCurrentHost(sink, target.Host)
		if progress != nil {
			progress.SetCurrentHost(target.Host)
		}
		if err := scanHost(scanCtx, target.Host, target.Source, resolvedTargets.DFSTargets, stateManager, inventory, credentialContextID, semantics, cfg.Scan.ForceRescan, recorder, cfg, engine, sink, logger); err != nil {
			if failure := authorityFailure(); failure != nil {
				return failure
			}
			if errors.Is(err, context.Canceled) && (errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink)) {
				operatorInterrupted = true
				return nil
			}
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				output.SetStatus(sink, "time limit reached")
				output.MarkTargetProcessed(sink)
				if progress != nil {
					progress.SetStatus("time limit reached")
					progress.MarkTargetProcessed()
				}
				break
			}
			errs = append(errs, err)
			output.MarkTargetProcessed(sink)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		if stateManager != nil {
			stateManager.MarkHostComplete(target.Host)
		}
		output.MarkTargetProcessed(sink)
		if progress != nil {
			progress.MarkTargetProcessed()
		}
	}
	scanTimer.Stop()
	if timedOut {
		output.SetStatus(sink, "time limit reached")
		if progress != nil {
			progress.SetStatus("time limit reached")
		}
		logger.Warnf("max scan time reached; stopping scan gracefully")
		return nil
	}
	if len(errs) > 0 {
		if failure := authorityFailure(); failure != nil {
			return failure
		}
		if errors.Is(errors.Join(errs...), context.Canceled) && (errors.Is(ctx.Err(), context.Canceled) || output.WasCanceledByUser(sink)) {
			operatorInterrupted = true
			return nil
		}
		return errors.Join(errs...)
	}
	if failure := authorityFailure(); failure != nil {
		return failure
	}
	return nil
}

type sqliteResumeReader struct {
	shadow            *store.SQLiteStore
	semanticsMatch    bool
	expectedSemantics string
}

func (r sqliteResumeReader) ResumeTargetComplete(host string) (bool, error) {
	if !r.semanticsMatch {
		return false, nil
	}
	return r.shadow.ResumeTargetComplete(host)
}

func (r sqliteResumeReader) ResumeShareComplete(host, share string) (bool, error) {
	if !r.semanticsMatch {
		return false, nil
	}
	return r.shadow.ResumeShareComplete(host, share)
}

func (r sqliteResumeReader) LookupFile(host, share, path string) (state.SQLiteFileState, bool, error) {
	file, found, err := r.shadow.LookupFile(host, share, path)
	if found && (r.expectedSemantics == "" || file.Semantics != r.expectedSemantics) {
		file.Status = "partial"
	}
	return state.SQLiteFileState{Key: file.Key, Host: file.Host, Share: file.Share, Path: file.Path, Status: file.Status, Semantics: file.Semantics, Size: file.Size, ModifiedAt: file.ModifiedAt, FirstSeen: file.FirstSeen, LastSeen: file.LastSeen, UpdatedAt: file.UpdatedAt}, found, err
}

func (r sqliteResumeReader) IsScopeExcluded(kind, host, share, path string) (bool, error) {
	if !r.semanticsMatch {
		return false, nil
	}
	return r.shadow.IsScopeExcluded(kind, host, share, path)
}

func replaySQLiteState(sink scanner.FindingSink, resume store.ResumeState) error {
	for _, finding := range resume.Findings {
		if !resume.FileWasCompleted(finding.Host, finding.Share, finding.FilePath) && finding.FilePath != "" {
			continue
		}
		if err := sink.WriteFinding(finding); err != nil {
			return err
		}
	}
	recorder, ok := sink.(scanner.CredentialCandidateSink)
	if !ok {
		return nil
	}
	for _, candidate := range resume.Credentials {
		if candidate.Path != "" && !resume.FileWasCompleted(candidate.Host, candidate.Share, candidate.Path) {
			continue
		}
		if err := recorder.RecordCredentialCandidate(candidate); err != nil {
			return err
		}
	}
	return nil
}

func scanHost(ctx context.Context, host, source string, dfsTargets []discovery.DFSTarget, stateManager *state.Manager, inventory *state.InventoryManager, credentialContextID, semantics string, forceRescan bool, recorder metrics.Recorder, cfg config.Config, engine *scanner.Engine, sink scanner.FindingSink, logger *logx.Logger) error {
	logger.Infof("scanning host %s", host)
	if observer, ok := sink.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}

	client := newScanClientFunc()
	client.SetMaxReadSize(scanReadLimit(cfg))
	defer client.Close()

	auth, err := smbAuthForHost(host, cfg.Scan)
	if err != nil {
		return err
	}
	if err := client.ConnectWithAuth(host, auth); err != nil {
		return fmt.Errorf("%s: connect failed: %w", host, err)
	}

	shares, err := client.ListShares()
	if err != nil {
		if len(cfg.Scan.Share) == 0 {
			return fmt.Errorf("%s: list shares failed: %w", host, err)
		}
		shares = configuredShareFallback(cfg.Scan)
		if len(shares) == 0 {
			return fmt.Errorf("%s: list shares failed: %w", host, err)
		}
		logger.Warnf("%s: share enumeration unavailable; using explicitly configured share(s)", host)
	}

	dfsHints := dfsHintsForHost(host, dfsTargets)
	if len(dfsHints) > 0 {
		logger.Infof("host %s has %d dfs-linked share hint(s)", host, len(dfsHints))
	}
	planFilters := planner.FilterOptions{
		IncludeShares: append([]string{}, cfg.Scan.Share...),
		ExcludeShares: append([]string{}, cfg.Scan.ExcludeShare...),
		IncludePaths:  append([]string{}, cfg.Scan.Path...),
		ExcludePaths:  append([]string{}, cfg.Scan.ExcludePath...),
		MaxDepth:      cfg.Scan.MaxDepth,
	}

	shareSet := make(map[string]struct{}, len(shares))
	shareInfoByName := make(map[string]smb.ShareInfo, len(shares))
	for _, share := range shares {
		key := strings.ToLower(strings.TrimSpace(share.Name))
		shareSet[key] = struct{}{}
		shareInfoByName[key] = share
	}
	for shareName := range dfsHints {
		if _, ok := shareSet[shareName]; ok {
			continue
		}
		resolvedShare := dfsHints[shareName].TargetShare
		if strings.TrimSpace(resolvedShare) == "" || !scanShareAllowed(resolvedShare, cfg.Scan) {
			continue
		}
		info := smb.ShareInfo{Name: resolvedShare}
		shares = append(shares, info)
		shareSet[shareName] = struct{}{}
		shareInfoByName[shareName] = info
		logger.Infof("adding dfs-linked share hint %s/%s to scan plan", host, resolvedShare)
	}

	shareInputs := make([]planner.ShareInput, 0, len(shares))
	for _, shareInfo := range shares {
		share := shareInfo.Name
		if !scanShareAllowed(share, cfg.Scan) {
			logger.Debugf("skipping share %s/%s due to share filters", host, share)
			continue
		}
		if cfg.Scan.OnlyADShares && !smb.IsADShare(share) {
			continue
		}
		shareSource := source
		if _, ok := dfsHints[strings.ToLower(strings.TrimSpace(share))]; ok {
			shareSource = "dfs"
		}
		shareInputs = append(shareInputs, planner.ShareInput{
			Host:               host,
			Share:              share,
			Source:             shareSource,
			PrioritizeADShares: cfg.Scan.PrioritizeADShares,
		})
	}
	plannedShares := planner.PlanShares(shareInputs, planFilters)
	if len(plannedShares) == 0 && len(cfg.Scan.Share) > 0 {
		return fmt.Errorf("%s: none of the explicitly requested shares are accessible", host)
	}
	shareScheduler := newShareScheduler(plannedShares)
	if stateManager != nil {
		shareScheduler.setSkipHandlers(
			func(plan planner.PlannedTarget) error { return stateManager.SkipShare(plan.Host, plan.Share) },
			func(plan planner.PlannedTarget, path string) error {
				return stateManager.SkipFolder(plan.Host, plan.Share, path)
			},
		)
	}
	output.SetShareScheduler(sink, shareScheduler.hooks())
	if recorder != nil {
		recorder.AddSharesEnumerated(len(plannedShares))
	}
	if cfg.Scan.OnlyADShares && len(plannedShares) == 0 {
		logger.Infof("no SYSVOL or NETLOGON shares available on %s", host)
	}

	bufferSize := cfg.Scan.WorkerCount * 2
	if bufferSize <= 0 {
		bufferSize = 2
	}

	jobs := make(chan scanner.Job, bufferSize)
	poolErrCh := make(chan error, 1)
	poolCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		poolErrCh <- scanner.NewWorkerPool(engine, sink, logger, recorder, cfg.Scan.WorkerCount).Scan(poolCtx, jobs)
	}()

	var walkErrs []error
	for {
		sharePlan, ok := shareScheduler.next()
		if !ok {
			break
		}
		if !forceRescan && stateManager != nil && stateManager.ShouldSkipShare(host, sharePlan.Share) {
			if stateManager.IsScopeExcluded("share", host, sharePlan.Share, "") {
				logger.Infof("resume: skipping excluded share %s/%s", host, sharePlan.Share)
			} else {
				logger.Infof("resume: skipping completed share %s/%s", host, sharePlan.Share)
			}
			shareScheduler.complete()
			continue
		}
		logger.Infof("walking %s/%s [priority=%d reason=%s]", host, sharePlan.Share, sharePlan.Priority, sharePlan.Reason)
		shareName := sharePlan.Share
		if observer, ok := sink.(scanner.ScanObserver); ok {
			observer.RecordShare(host, shareName)
		}
		dfsHint, hasDFSHint := dfsHints[strings.ToLower(strings.TrimSpace(shareName))]
		if stateManager != nil {
			stateManager.StartShare(host, shareName)
		}

		fileInputs := make([]planner.FileInput, 0, sharePlanningBatchSize)
		fileIndex := make(map[string]smb.RemoteFile, sharePlanningBatchSize)
		skippedBundleCandidates := make(map[artifactbundle.BundleKey]map[artifact.Kind]bundleCandidate)
		rehydratedBundleCandidates := make(map[artifactbundle.BundleKey]map[artifact.Kind]bool)
		changedBundles := make(map[artifactbundle.BundleKey]map[artifact.Kind]bool)
		flushBatch := func() error {
			if len(fileInputs) == 0 {
				return nil
			}

			plannedFiles := planner.PlanFiles(fileInputs, planFilters)
			queuedThisBatch := 0
			enqueue := func(remote smb.RemoteFile, filePlan planner.PlannedTarget, inventoryKey string, dependency bool) error {
				shareInfo := shareInfoByName[strings.ToLower(strings.TrimSpace(remote.Share))]
				meta := scanner.FileMetadata{
					Host: remote.Host, Share: remote.Share, ShareDescription: shareInfo.Description, ShareType: shareInfo.Type,
					SharePriority: sharePlan.Priority, SharePriorityReason: sharePlan.Reason, FilePath: remote.Path,
					Source: sharePlan.Source, Priority: filePlan.Priority, PriorityReason: filePlan.Reason, Name: remote.Name,
					Extension: remote.Extension, Size: remote.Size, ModifiedAt: remote.ModifiedAt, IsDir: remote.IsDir,
					FromSYSVOL: strings.EqualFold(remote.Share, "SYSVOL"), FromNETLOGON: strings.EqualFold(remote.Share, "NETLOGON"),
					BundleDependency: dependency,
				}
				if hasDFSHint {
					meta.Source = "dfs"
					meta.DFSNamespacePath = dfsHint.NamespacePath
					meta.DFSLinkPath = dfsHint.LinkPath
				}
				remotePath := remote.Path
				job := scanner.Job{Metadata: meta, LoadContent: func(ctx context.Context, _ scanner.FileMetadata) ([]byte, error) {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					default:
					}
					return client.ReadFile(shareName, strings.ReplaceAll(remotePath, "/", `\`))
				}, OnComplete: func(meta scanner.FileMetadata, evaluation scanner.Evaluation, err error) {
					if dependency {
						return
					}
					if stateManager != nil && inventory == nil {
						stateManager.RecordFileResult(meta.Host, meta.Share, meta.FilePath, meta.Size, meta.ModifiedAt, err == nil)
					} else if stateManager != nil {
						stateManager.RecordFileResultInMemory(meta.Host, meta.Share, meta.FilePath, meta.Size, meta.ModifiedAt, err == nil)
					}
					if inventory == nil {
						return
					}
					if err != nil {
						inventory.MarkFailed(inventoryKey)
						return
					}
					if evaluation.Skipped && evaluation.NeedContent {
						inventory.MarkPartial(inventoryKey)
						return
					}
					if len(evaluation.InspectionFailures) > 0 {
						// Read succeeded but content could not be fully inspected
						// (for example an encrypted legacy document): the object
						// must not be recorded as completed.
						inventory.MarkPartial(inventoryKey)
						return
					}
					inventory.MarkCompleted(inventoryKey)
				}}
				if inventory != nil && !dependency {
					inventory.MarkScanning(inventoryKey)
				}
				select {
				case <-poolCtx.Done():
					return poolCtx.Err()
				case jobs <- job:
					queuedThisBatch++
				}
				return nil
			}
			for _, filePlan := range plannedFiles {
				remote, ok := fileIndex[strings.ToLower(filePlan.Path)]
				if !ok {
					continue
				}
				var inventoryKey string
				kind, isBundleArtifact := bundleKind(remote)
				bundleKey := artifactbundle.KeyFor(artifact.Origin{Host: remote.Host, Share: remote.Share, ContainerPath: remote.Path, ContainerType: "loose"})
				if inventory != nil {
					decision, err := inventory.Prepare(state.FileObservation{
						Server: remote.Host, Share: remote.Share, Path: remote.Path,
						Size: remote.Size, ModifiedAt: remote.ModifiedAt,
					}, credentialContextID, semantics, forceRescan)
					if err != nil {
						logger.Warnf("scan-state lookup ignored for %s/%s/%s: %v", remote.Host, remote.Share, remote.Path, err)
					} else if decision.Skip {
						logger.Debugf("scan-state: skipping unchanged file %s/%s/%s", remote.Host, remote.Share, remote.Path)
						if isBundleArtifact {
							candidates := skippedBundleCandidates[bundleKey]
							if candidates == nil {
								candidates = make(map[artifact.Kind]bundleCandidate)
								skippedBundleCandidates[bundleKey] = candidates
							}
							candidates[kind] = bundleCandidate{remote: remote, filePlan: filePlan}
						}
						continue
					} else {
						inventoryKey = decision.Key
					}
				} else if stateManager != nil && stateManager.ShouldSkipFile(remote.Host, remote.Share, remote.Path, remote.Size, remote.ModifiedAt) {
					logger.Debugf("resume: skipping completed file %s/%s/%s", remote.Host, remote.Share, remote.Path)
					continue
				}

				if isBundleArtifact {
					if changedBundles[bundleKey] == nil {
						changedBundles[bundleKey] = make(map[artifact.Kind]bool)
					}
					changedBundles[bundleKey][kind] = true
				}
				if err := enqueue(remote, filePlan, inventoryKey, false); err != nil {
					return err
				}
			}
			for _, dependency := range collectBundleDependencies(changedBundles, skippedBundleCandidates, rehydratedBundleCandidates) {
				if err := enqueue(dependency.remote, dependency.filePlan, "", true); err != nil {
					return err
				}
			}
			if stateManager != nil {
				stateManager.AddPendingFiles(host, shareName, queuedThisBatch)
			}

			clear(fileIndex)
			fileInputs = fileInputs[:0]
			return nil
		}

		err := client.WalkShareWithOptions(shareName, smb.WalkOptions{
			IncludePaths: append([]string{}, cfg.Scan.Path...),
			ExcludePaths: append([]string{}, cfg.Scan.ExcludePath...),
			MaxDepth:     cfg.Scan.MaxDepth,
			ShouldDescend: func(path string) bool {
				if shareScheduler.shouldDescend(path) {
					return stateManager == nil || stateManager.ShouldDescend(host, shareName, path)
				}
				return false
			},
			CurrentDirectory: shareScheduler.setCurrentDirectory,
		}, func(remote smb.RemoteFile) error {
			if shareScheduler.consumeDefer(sharePlan) {
				return errShareDeferred
			}
			if remote.IsDir {
				return nil
			}
			if shareScheduler.isCurrentSkipped() {
				return nil
			}
			fileSource := sharePlan.Source
			if hasDFSHint {
				fileSource = "dfs"
			}
			fileInputs = append(fileInputs, planner.FileInput{
				Host:               remote.Host,
				Share:              remote.Share,
				Path:               remote.Path,
				Extension:          remote.Extension,
				Source:             fileSource,
				PrioritizeADShares: cfg.Scan.PrioritizeADShares,
			})
			fileIndex[strings.ToLower(remote.Path)] = remote
			if len(fileInputs) >= sharePlanningBatchSize {
				return flushBatch()
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, errShareDeferred) {
				logger.Infof("deferring remaining work for %s/%s", host, shareName)
				continue
			}
			logger.Warnf("walk failed for %s/%s: %v", host, shareName, err)
			if stateManager != nil {
				stateManager.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			shareScheduler.complete()
			continue
		}
		if shareScheduler.consumeDefer(sharePlan) {
			if err := flushBatch(); err != nil {
				walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
				shareScheduler.complete()
				continue
			}
			logger.Infof("deferring remaining work for %s/%s", host, shareName)
			continue
		}
		if err := flushBatch(); err != nil {
			if stateManager != nil {
				stateManager.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			shareScheduler.complete()
			continue
		}
		if stateManager != nil {
			stateManager.FinishShareEnumeration(host, shareName)
		}
		shareScheduler.complete()
	}

	close(jobs)
	poolErr := <-poolErrCh
	if poolErr != nil {
		return poolErr
	}
	if len(walkErrs) > 0 {
		return errors.Join(walkErrs...)
	}
	if stateManager != nil && !stateManager.HostComplete(host, len(plannedShares)) {
		return fmt.Errorf("%s: scan coverage incomplete; one or more shares did not complete", host)
	}
	return nil
}

// collectBundleDependencies returns unchanged companion artifacts required to
// recompute bundles affected by this run. Bundle keys retain the origin
// boundary, so a same-named artifact from another directory/container cannot
// be selected as a dependency.
func collectBundleDependencies(
	changed map[artifactbundle.BundleKey]map[artifact.Kind]bool,
	candidates map[artifactbundle.BundleKey]map[artifact.Kind]bundleCandidate,
	rehydrated map[artifactbundle.BundleKey]map[artifact.Kind]bool,
) []bundleCandidate {
	keys := make([]artifactbundle.BundleKey, 0, len(changed))
	for key := range changed {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bundleKeyString(keys[i]) < bundleKeyString(keys[j])
	})
	result := make([]bundleCandidate, 0)
	for _, key := range keys {
		changedKinds := changed[key]
		kinds := make([]artifact.Kind, 0, len(candidates[key]))
		for kind := range candidates[key] {
			kinds = append(kinds, kind)
		}
		sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
		for _, kind := range kinds {
			if changedKinds[kind] || rehydrated[key][kind] {
				continue
			}
			if rehydrated[key] == nil {
				rehydrated[key] = make(map[artifact.Kind]bool)
			}
			rehydrated[key][kind] = true
			result = append(result, candidates[key][kind])
		}
	}
	return result
}

func bundleKeyString(key artifactbundle.BundleKey) string {
	return strings.Join([]string{key.Host, key.Share, key.Scope, key.Context}, "\x00")
}

func smbAuthForHost(host string, cfg config.ScanConfig) (smb.Auth, error) {
	smbAuthMode := strings.ToLower(strings.TrimSpace(cfg.SMBAuth))
	switch smb.AuthMode(smbAuthMode) {
	case smb.AuthModeNTHash:
		return smb.NewNTHashAuth(cfg.Username, cfg.Domain, cfg.NTHash)
	case smb.AuthModeKerberos:
		spn, err := resolveSMBSPN(host, cfg.SMBHostname, cfg.SMBSPN)
		if err != nil {
			return smb.Auth{}, err
		}
		return smb.NewKerberosAuth(cfg.Username, cfg.Domain, cfg.KerberosCCache, spn), nil
	default:
		return smb.NewPasswordAuth(cfg.Username, cfg.Domain, cfg.Password), nil
	}
}

type scanSemantics struct {
	SchemaVersion    int
	ScannerVersion   string
	Profile          string
	AuthMode         string
	SMBAuth          string
	Username         string
	Domain           string
	SMBHostname      string
	SMBSPN           string
	Share            []string
	ExcludeShare     []string
	Path             []string
	ExcludePath      []string
	MaxDepth         int
	OnlyADShares     bool
	DiscoverDFS      bool
	MaxFileSize      int64
	MaxReadBytes     int64
	Archives         config.ArchiveConfig
	WIM              config.WIMConfig
	SQLite           config.SQLiteConfig
	RulesFingerprint string
}

// scannerSemanticsVersion is part of the incremental reuse decision: a change
// here makes every previously completed object eligible for re-inspection.
//
// It must be bumped when content parsing or classification behaviour changes
// without changing the rule fingerprint, so state produced by an older engine
// is not silently trusted.
//
// v4 (natural-language credential detection):
//   - short explicit password values ("Passordet er; 8392") are no longer
//     refused by the generic six-rune inference floor
//   - a bounded explicit expression may follow ordinary prefix text on the same
//     logical line
//   - a bounded subject phrase between label and copula
//     ("Passordet for nettverket er; <value>") is recognised
//   - the Norwegian definite identity labels (brukernavnet, brukeren) classify
//
// v3 (natural-language credential expressions):
//   - shared grammar for "Passordet er; <value>" / "Password is <value>" and the
//     matching identity/domain phrases, applied to every text-bearing source
//
// v2 (Office credential harvesting):
//   - reconstructed DOCX/XLSX/PPTX logical text (paragraphs, tables, rows)
//   - rendered OOXML parts (footnotes, comments, diagrams, drawings, Excel comments)
//   - DOCX header-row credential tables in the shared table renderer
const scannerSemanticsVersion = "snablr-content-scan-v4"

func scanSemanticsFingerprint(cfg config.Config, manager *rules.Manager) string {
	return scanSemanticsFingerprintWithVersion(cfg, manager, scannerSemanticsVersion)
}

func scanSemanticsFingerprintWithVersion(cfg config.Config, manager *rules.Manager, version string) string {
	ruleFingerprint := ""
	if manager != nil {
		ruleFingerprint = state.SemanticsFingerprint(manager.EnabledRules())
	}
	return state.SemanticsFingerprint(scanSemantics{
		SchemaVersion:    1,
		ScannerVersion:   version,
		Profile:          strings.TrimSpace(cfg.Scan.Profile),
		AuthMode:         strings.ToLower(strings.TrimSpace(cfg.Scan.AuthMode)),
		SMBAuth:          strings.ToLower(strings.TrimSpace(cfg.Scan.SMBAuth)),
		Username:         strings.ToLower(strings.TrimSpace(cfg.Scan.Username)),
		Domain:           strings.ToLower(strings.TrimSpace(cfg.Scan.Domain)),
		SMBHostname:      strings.ToLower(strings.TrimSpace(cfg.Scan.SMBHostname)),
		SMBSPN:           strings.ToLower(strings.TrimSpace(cfg.Scan.SMBSPN)),
		Share:            sortedScanScope(cfg.Scan.Share),
		ExcludeShare:     sortedScanScope(cfg.Scan.ExcludeShare),
		Path:             sortedScanScope(cfg.Scan.Path),
		ExcludePath:      sortedScanScope(cfg.Scan.ExcludePath),
		MaxDepth:         cfg.Scan.MaxDepth,
		OnlyADShares:     cfg.Scan.OnlyADShares,
		DiscoverDFS:      cfg.Scan.DiscoverDFS,
		MaxFileSize:      cfg.Scan.MaxFileSize,
		MaxReadBytes:     scanReadLimit(cfg),
		Archives:         cfg.Archives,
		WIM:              cfg.WIM,
		SQLite:           cfg.SQLite,
		RulesFingerprint: ruleFingerprint,
	})
}

func sortedScanScope(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, `\`, "/")))
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func sqliteStatePath(cfg config.Config) string {
	if path := strings.TrimSpace(cfg.Scan.SQLiteStateFile); path != "" {
		return path
	}
	for _, candidate := range []string{cfg.Output.HTMLOut, cfg.Output.JSONOut, cfg.Output.MDOut, cfg.Output.CSVOut, cfg.Output.CredsOut, cfg.Output.ScannedTargetsOut} {
		if candidate = strings.TrimSpace(candidate); candidate != "" && candidate != "-" {
			return filepath.Join(filepath.Dir(candidate), "snablr.db")
		}
	}
	return "snablr.db"
}

// DefaultSQLiteStatePath returns the scan database path used when no output
// or SQLite override is configured. Findings viewers use this same resolver.
func DefaultSQLiteStatePath() string {
	return sqliteStatePath(config.Config{})
}

func resolveSMBSPN(target, hostname, override string) (string, error) {
	if value := strings.TrimSpace(override); value != "" {
		return value, nil
	}
	host := strings.TrimSpace(hostname)
	if host == "" {
		host = strings.TrimSpace(target)
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	}
	if host == "" || net.ParseIP(host) != nil {
		return "", fmt.Errorf("SMB Kerberos requires --smb-hostname or --smb-spn for IP targets")
	}
	return "cifs/" + strings.ToLower(strings.TrimSuffix(host, ".")), nil
}

func scanReadLimit(cfg config.Config) int64 {
	limit := cfg.Scan.MaxFileSize
	if cfg.Archives.Enabled {
		if cfg.Archives.AutoZIPMaxSize > limit {
			limit = cfg.Archives.AutoZIPMaxSize
		}
		if cfg.Archives.AllowLargeZIPs && cfg.Archives.MaxZIPSize > limit {
			limit = cfg.Archives.MaxZIPSize
		}
		if cfg.Archives.AutoTARMaxSize > limit {
			limit = cfg.Archives.AutoTARMaxSize
		}
		if cfg.Archives.AllowLargeTARs && cfg.Archives.MaxTARSize > limit {
			limit = cfg.Archives.MaxTARSize
		}
	}
	if cfg.WIM.Enabled {
		if cfg.WIM.AutoWIMMaxSize > limit {
			limit = cfg.WIM.AutoWIMMaxSize
		}
		if cfg.WIM.AllowLargeWIMs && cfg.WIM.MaxWIMSize > limit {
			limit = cfg.WIM.MaxWIMSize
		}
	}
	if cfg.SQLite.Enabled {
		if cfg.SQLite.AutoDBMaxSize > limit {
			limit = cfg.SQLite.AutoDBMaxSize
		}
		if cfg.SQLite.AllowLargeDBs && cfg.SQLite.MaxDBSize > limit {
			limit = cfg.SQLite.MaxDBSize
		}
	}
	return limit
}

func scanShareAllowed(share string, cfg config.ScanConfig) bool {
	share = strings.ToLower(strings.TrimSpace(share))
	if share == "" {
		return false
	}
	if len(cfg.Share) > 0 {
		matched := false
		for _, allowed := range cfg.Share {
			if share == strings.ToLower(strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, blocked := range cfg.ExcludeShare {
		if share == strings.ToLower(strings.TrimSpace(blocked)) {
			return false
		}
	}
	return true
}

func configuredShareFallback(cfg config.ScanConfig) []smb.ShareInfo {
	shares := make([]smb.ShareInfo, 0, len(cfg.Share))
	seen := make(map[string]struct{}, len(cfg.Share))
	for _, share := range cfg.Share {
		name := strings.TrimSpace(share)
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok || !scanShareAllowed(name, cfg) || (cfg.OnlyADShares && !smb.IsADShare(name)) {
			continue
		}
		seen[key] = struct{}{}
		shares = append(shares, smb.ShareInfo{Name: name})
	}
	return shares
}

func dfsHintsForHost(host string, targets []discovery.DFSTarget) map[string]discovery.DFSTarget {
	hints := make(map[string]discovery.DFSTarget)
	host = strings.ToLower(strings.TrimSpace(host))
	for _, target := range targets {
		server := strings.ToLower(strings.TrimSpace(target.TargetServer))
		if host == "" || server == "" || host != server {
			continue
		}
		shareKey := strings.ToLower(strings.TrimSpace(target.TargetShare))
		if shareKey == "" {
			continue
		}
		if _, ok := hints[shareKey]; ok {
			continue
		}
		hints[shareKey] = target
	}
	return hints
}

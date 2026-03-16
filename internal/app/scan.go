package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/output"
	"snablr/internal/planner"
	"snablr/internal/scanner"
	"snablr/internal/smb"
	"snablr/internal/state"
	"snablr/internal/ui"
	"snablr/pkg/logx"
)

const sharePlanningBatchSize = 2048

func RunScan(ctx context.Context, opts ScanOptions) (err error) {
	cfg, logger, err := loadConfigAndLogger(opts.ConfigPath, opts.LogLevel)
	if err != nil {
		return err
	}

	applyScanOverrides(&cfg, opts)
	if err := validateScanConfig(cfg); err != nil {
		return err
	}
	cfg.Scan.WorkerCount = scanner.ResolveWorkerCount(cfg.Scan.WorkerCount)
	logger.Infof("using %d file scan worker(s)", cfg.Scan.WorkerCount)

	scanCtx := ctx
	var cancel context.CancelFunc
	maxScanDuration, err := cfg.Scan.MaxScanDuration()
	if err != nil {
		return err
	}
	if maxScanDuration > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, maxScanDuration)
		defer cancel()
	}

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

	sink, err := output.NewWriter(cfg.Output)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	defer func() {
		if sink == nil {
			return
		}
		if closeErr := sink.Close(); closeErr != nil {
			if logger != nil {
				logger.Errorf("output finalization failed: %v", closeErr)
			}
			if err == nil {
				err = closeErr
			}
		}
	}()

	if strings.TrimSpace(cfg.Scan.Baseline) != "" {
		baseline, err := diff.LoadJSON(cfg.Scan.Baseline)
		if err != nil {
			return fmt.Errorf("load baseline %s: %w", cfg.Scan.Baseline, err)
		}
		output.SetBaselineFindings(sink, baseline.Findings)
		logger.Infof("loaded %d baseline finding(s) for diff reporting", len(baseline.Findings))
	}

	recorder := metrics.NewCollector()
	totalTimer := recorder.StartPhase("total_scan")
	defer func() {
		totalTimer.Stop()
		output.SetMetricsSnapshot(sink, recorder.Snapshot())
	}()

	checkpoints, err := state.NewManager(cfg.Scan.CheckpointFile, cfg.Scan.Resume, 10*time.Second)
	if err != nil {
		return fmt.Errorf("open checkpoint state: %w", err)
	}
	if checkpoints != nil {
		checkpoints.Start(scanCtx)
		defer checkpoints.Close()
	}

	engine := scanner.NewEngine(scanner.Options{
		Workers:          cfg.Scan.WorkerCount,
		MaxFileSizeBytes: cfg.Scan.MaxFileSize,
		MaxReadBytes:     cfg.Scan.MaxFileSize,
		SnippetBytes:     120,
		Recorder:         recorder,
	}, manager, sink, logger)

	resolvedTargets, err := discovery.Resolve(scanCtx, cfg.Scan, logger, recorder)
	if err != nil {
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

	var progress *ui.ProgressReporter
	if ui.ShouldShowProgress(cfg.Output.Format) {
		progress = ui.NewProgressReporter(os.Stderr, recorder, 3*time.Second)
		progress.SetTargetTotal(len(plannedHosts))
		progress.Start(scanCtx)
		defer progress.Close()
	}

	var errs []error
	timedOut := false
	scanTimer := recorder.StartPhase("host_scanning")
	for _, target := range plannedHosts {
		if err := scanCtx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				break
			}
			return err
		}
		if checkpoints != nil && checkpoints.ShouldSkipHost(target.Host) {
			logger.Infof("resume: skipping completed host %s", target.Host)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		if progress != nil {
			progress.SetCurrentHost(target.Host)
		}
		if err := scanHost(scanCtx, target.Host, target.Source, resolvedTargets.DFSTargets, checkpoints, recorder, cfg, engine, sink, logger); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				timedOut = true
				if progress != nil {
					progress.SetStatus("time limit reached")
					progress.MarkTargetProcessed()
				}
				break
			}
			errs = append(errs, err)
			if progress != nil {
				progress.MarkTargetProcessed()
			}
			continue
		}
		if checkpoints != nil {
			checkpoints.MarkHostComplete(target.Host)
		}
		if progress != nil {
			progress.MarkTargetProcessed()
		}
	}
	scanTimer.Stop()
	if timedOut {
		if progress != nil {
			progress.SetStatus("time limit reached")
		}
		logger.Warnf("max scan time reached; stopping scan gracefully")
		return nil
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func scanHost(ctx context.Context, host, source string, dfsTargets []discovery.DFSTarget, checkpoints *state.Manager, recorder metrics.Recorder, cfg config.Config, engine *scanner.Engine, sink scanner.FindingSink, logger *logx.Logger) error {
	logger.Infof("scanning host %s", host)
	if observer, ok := sink.(scanner.ScanObserver); ok {
		observer.RecordHost(host)
	}

	client := smb.NewClient()
	defer client.Close()

	if err := client.Connect(host, cfg.Scan.Username, cfg.Scan.Password); err != nil {
		return fmt.Errorf("%s: connect failed: %w", host, err)
	}

	shares, err := client.ListShares()
	if err != nil {
		return fmt.Errorf("%s: list shares failed: %w", host, err)
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
	for _, sharePlan := range plannedShares {
		if checkpoints != nil && checkpoints.ShouldSkipShare(host, sharePlan.Share) {
			logger.Infof("resume: skipping completed share %s/%s", host, sharePlan.Share)
			continue
		}
		logger.Infof("walking %s/%s [priority=%d reason=%s]", host, sharePlan.Share, sharePlan.Priority, sharePlan.Reason)
		shareName := sharePlan.Share
		if observer, ok := sink.(scanner.ScanObserver); ok {
			observer.RecordShare(host, shareName)
		}
		dfsHint, hasDFSHint := dfsHints[strings.ToLower(strings.TrimSpace(shareName))]
		if checkpoints != nil {
			checkpoints.StartShare(host, shareName)
		}

		fileInputs := make([]planner.FileInput, 0, sharePlanningBatchSize)
		fileIndex := make(map[string]smb.RemoteFile, sharePlanningBatchSize)
		flushBatch := func() error {
			if len(fileInputs) == 0 {
				return nil
			}

			plannedFiles := planner.PlanFiles(fileInputs, planFilters)
			queuedThisBatch := 0
			for _, filePlan := range plannedFiles {
				remote, ok := fileIndex[strings.ToLower(filePlan.Path)]
				if !ok {
					continue
				}
				if checkpoints != nil && checkpoints.ShouldSkipFile(remote.Host, remote.Share, remote.Path) {
					logger.Debugf("resume: skipping completed file %s/%s/%s", remote.Host, remote.Share, remote.Path)
					continue
				}

				shareInfo := shareInfoByName[strings.ToLower(strings.TrimSpace(remote.Share))]
				meta := scanner.FileMetadata{
					Host:             remote.Host,
					Share:            remote.Share,
					ShareDescription: shareInfo.Description,
					ShareType:        shareInfo.Type,
					FilePath:         remote.Path,
					Source:           sharePlan.Source,
					Priority:         filePlan.Priority,
					PriorityReason:   filePlan.Reason,
					Name:             remote.Name,
					Extension:        remote.Extension,
					Size:             remote.Size,
					IsDir:            remote.IsDir,
					FromSYSVOL:       strings.EqualFold(remote.Share, "SYSVOL"),
					FromNETLOGON:     strings.EqualFold(remote.Share, "NETLOGON"),
				}
				if hasDFSHint {
					meta.Source = "dfs"
					meta.DFSNamespacePath = dfsHint.NamespacePath
					meta.DFSLinkPath = dfsHint.LinkPath
				}

				remotePath := remote.Path
				job := scanner.Job{
					Metadata: meta,
					LoadContent: func(ctx context.Context, _ scanner.FileMetadata) ([]byte, error) {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						default:
						}
						return client.ReadFile(shareName, strings.ReplaceAll(remotePath, "/", `\`))
					},
					OnComplete: func(meta scanner.FileMetadata, _ scanner.Evaluation, err error) {
						if checkpoints == nil {
							return
						}
						checkpoints.RecordFileResult(meta.Host, meta.Share, meta.FilePath, err == nil)
					},
				}

				select {
				case <-poolCtx.Done():
					return poolCtx.Err()
				case jobs <- job:
					queuedThisBatch++
				}
			}

			if checkpoints != nil {
				checkpoints.AddPendingFiles(host, shareName, queuedThisBatch)
			}

			clear(fileIndex)
			fileInputs = fileInputs[:0]
			return nil
		}

		err := client.WalkShareWithOptions(shareName, smb.WalkOptions{
			IncludePaths: append([]string{}, cfg.Scan.Path...),
			ExcludePaths: append([]string{}, cfg.Scan.ExcludePath...),
			MaxDepth:     cfg.Scan.MaxDepth,
		}, func(remote smb.RemoteFile) error {
			if remote.IsDir {
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
			logger.Warnf("walk failed for %s/%s: %v", host, shareName, err)
			if checkpoints != nil {
				checkpoints.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			continue
		}
		if err := flushBatch(); err != nil {
			if checkpoints != nil {
				checkpoints.AbortShare(host, shareName)
			}
			walkErrs = append(walkErrs, fmt.Errorf("%s/%s: %w", host, shareName, err))
			continue
		}
		if checkpoints != nil {
			checkpoints.FinishShareEnumeration(host, shareName)
		}
	}

	close(jobs)
	poolErr := <-poolErrCh
	if poolErr != nil {
		return poolErr
	}
	if len(walkErrs) > 0 {
		return errors.Join(walkErrs...)
	}
	return nil
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

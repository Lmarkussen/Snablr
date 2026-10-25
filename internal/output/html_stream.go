package output

import (
	"context"
	"fmt"
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/diff"
	"snablr/internal/scanner"
	"snablr/internal/store"
	"snablr/internal/version"
)

func (h *HTMLWriter) closeAttachedSQLite(shadow *store.SQLiteStore) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iterator, err := persistedReportIteratorContext(ctx, shadow)
	if err != nil {
		return fmt.Errorf("prepare persisted HTML iterator: %w", err)
	}
	var index *HTMLReportIndex
	if h.baselinePath != "" {
		index, err = BuildHTMLReportIndexWithBaselineIterator(ctx, iterator, func(ctx context.Context, visit func(scanner.Finding) error) error {
			return diff.StreamJSONFindings(ctx, h.baselinePath, visit)
		})
	} else if h.baseline != nil {
		index, err = BuildHTMLReportIndexWithBaseline(ctx, iterator, h.baseline)
	} else {
		index, err = BuildHTMLReportIndex(ctx, iterator)
	}
	if err != nil {
		return fmt.Errorf("build disk-backed HTML index: %w", err)
	}
	defer index.Close()
	if !h.writeOnClose && !h.interrupted {
		if h.closer != nil {
			return h.closer.Close()
		}
		return nil
	}
	analysis, err := credentialanalysis.NewPersistedAnalysis()
	if err != nil {
		return fmt.Errorf("prepare persisted credential analysis: %w", err)
	}
	defer analysis.Close()
	if err := shadow.IterateCredentials(ctx, 256, func(batch []credentialanalysis.Candidate) error {
		for _, candidate := range batch {
			if err := analysis.Add(ctx, candidate); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("merge persisted credential candidates: %w", err)
	}
	primarySummaries, err := index.CategorySummaries(ctx, true)
	if err != nil {
		return err
	}
	supportingSummaries, err := index.CategorySummaries(ctx, false)
	if err != nil {
		return err
	}
	primaryCount, err := index.GroupCount(ctx, true)
	if err != nil {
		return err
	}
	supportingCount, err := index.GroupCount(ctx, false)
	if err != nil {
		return err
	}
	filterOptions, err := index.FilterOptions(ctx)
	if err != nil {
		return err
	}
	hostSummaries, err := index.HostSummaries(ctx)
	if err != nil {
		return err
	}
	topAccessPaths, err := index.TopAccessPaths(ctx, 8)
	if err != nil {
		return err
	}
	validation, err := buildValidationSummaryIterator(h.manifest, func(visit func(scanner.Finding) error) error {
		return iterator(ctx, visit)
	})
	if err != nil {
		return fmt.Errorf("validate persisted HTML findings: %w", err)
	}
	primaryGroups, primaryErr := streamHTMLGroups(ctx, index, true)
	supportingGroups, supportingErr := streamHTMLGroups(ctx, index, false)
	var diffSummary *diff.Summary
	var changedFindings, removedFindings any
	var changedCount, removedCount int
	var changedErr, removedErr <-chan error
	if h.baselinePath != "" || h.baseline != nil {
		diffSummary, err = index.DiffSummary(ctx)
		if err != nil {
			return err
		}
		changedCount = diffSummary.Changed
		removedCount = diffSummary.Removed
		changedFindings, changedErr = index.streamChanged(ctx)
		removedFindings, removedErr = index.streamRemoved(ctx)
	}
	stats := analysis.Stats()
	var correlations []credentialanalysis.Correlation
	if err := analysis.IterateCorrelations(ctx, func(correlation credentialanalysis.Correlation) error {
		correlations = append(correlations, correlation)
		return nil
	}); err != nil {
		return fmt.Errorf("build persisted credential correlations: %w", err)
	}
	data := htmlReportData{
		Version:                     version.Short(),
		Profile:                     h.profile,
		Summary:                     h.summary.Snapshot(),
		Metrics:                     h.metrics,
		CategorySummaries:           htmlCategorySummaries(primarySummaries),
		SupportingCategorySummaries: htmlCategorySummaries(supportingSummaries),
		CategoryGroups:              primaryGroups,
		SupportingCategoryGroups:    supportingGroups,
		SupportingCategoryCount:     len(supportingSummaries),
		SupportingFindingCount:      supportingCount,
		HostSummaries:               hostSummaries,
		AccessPaths:                 topAccessPaths,
		TopAccessPaths:              topAccessPaths,
		RenderAccessPaths:           true,
		FilterOptions:               filterOptions,
		Validation:                  validation,
		DiffSummary:                 diffSummary,
		ChangedFindings:             changedFindings,
		RemovedFindings:             removedFindings,
		ChangedFindingCount:         changedCount,
		RemovedFindingCount:         removedCount,
		CredentialAnalysis: credentialanalysis.Report{
			CandidatesAnalyzed: stats.CandidatesAnalyzed, SuppressedPlaceholders: stats.SuppressedPlaceholders,
			SuppressedWeakReview: stats.SuppressedWeakReview, DuplicatesMerged: stats.DuplicatesMerged,
			Correlations: correlations,
		},
		Interrupted:        h.interrupted,
		InterruptionReason: h.interruption,
	}
	_ = primaryCount
	var anchorErr error
	credentialView, credentialErr, err := buildPersistedCredentialReportView(ctx, analysis, func(candidate credentialanalysis.SafeCandidate) string {
		paths := []string{candidate.Path}
		for _, evidence := range candidate.Evidence {
			paths = append(paths, evidence.Path)
		}
		if candidate.Container != "" && !strings.Contains(candidate.Path, "!") {
			paths = append(paths, candidate.Container+"!"+candidate.Path)
		}
		for _, path := range paths {
			if strings.TrimSpace(path) == "" {
				continue
			}
			anchor, found, err := index.CredentialAnchorForProvenance(ctx, candidate.Host, candidate.Share, path)
			if err != nil {
				anchorErr = err
				return ""
			}
			if found {
				return anchor
			}
		}
		return ""
	})
	if anchorErr != nil {
		return fmt.Errorf("resolve HTML credential anchors: %w", anchorErr)
	}
	data.CredentialView = credentialView
	if err := h.template.ExecuteTemplate(h.w, "report.document-shell", data); err != nil {
		if h.closer != nil {
			_ = h.closer.Close()
		}
		return err
	}
	if err := <-primaryErr; err != nil {
		if h.closer != nil {
			_ = h.closer.Close()
		}
		return err
	}
	if err := <-supportingErr; err != nil {
		if h.closer != nil {
			_ = h.closer.Close()
		}
		return err
	}
	for _, streamErr := range []<-chan error{changedErr, removedErr} {
		if streamErr != nil {
			if err := <-streamErr; err != nil {
				if h.closer != nil {
					_ = h.closer.Close()
				}
				return err
			}
		}
	}
	if credentialErr != nil {
		if err := <-credentialErr; err != nil {
			if h.closer != nil {
				_ = h.closer.Close()
			}
			return fmt.Errorf("render persisted credential analysis: %w", err)
		}
	}
	if atomic, ok := h.closer.(*atomicOutput); ok {
		atomic.commit = true
	}
	if h.closer == nil {
		return nil
	}
	return h.closer.Close()
}

func htmlCategorySummaries(input []HTMLReportCategorySummary) []categorySummary {
	if len(input) == 0 {
		return nil
	}
	out := make([]categorySummary, 0, len(input))
	for _, summary := range input {
		out = append(out, categorySummary{
			Category:            summary.Category,
			Findings:            summary.Findings,
			Critical:            summary.Critical,
			High:                summary.High,
			Medium:              summary.Medium,
			Low:                 summary.Low,
			HighestSeverity:     summary.HighestSeverity,
			RemediationGuidance: remediationGuidanceForCategory(summary.Category),
		})
	}
	return out
}

func streamHTMLGroups(ctx context.Context, index *HTMLReportIndex, primary bool) (<-chan htmlCategoryGroup, <-chan error) {
	out := make(chan htmlCategoryGroup)
	errors := make(chan error, 1)
	go func() {
		defer close(out)
		err := index.ForEachGroup(ctx, primary, func(group HTMLReportGroup) error {
			finding, err := index.Canonical(ctx, group.Key)
			if err != nil {
				return err
			}
			search, scope, err := index.GroupMetadata(ctx, group.Key)
			if err != nil {
				return err
			}
			duplicates := index.streamDuplicates(ctx, group.Key)
			status, changedFields, err := index.DiffStatus(ctx, finding)
			if err != nil {
				return err
			}
			item := htmlFinding{
				Finding:         finding,
				DiffStatus:      status,
				ChangedFields:   changedFields,
				SearchText:      search,
				ScopeText:       scope,
				DuplicateStream: duplicates,
				DuplicateCount:  group.DuplicateCount,
				TotalLocations:  group.FindingCount,
			}
			select {
			case out <- htmlCategoryGroup{Summary: categorySummary{Category: group.Category, Findings: group.FindingCount, HighestSeverity: finding.Severity, RemediationGuidance: remediationGuidanceForCategory(group.Category)}, Findings: []htmlFinding{item}}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		errors <- err
		close(errors)
	}()
	return out, errors
}

func (i *HTMLReportIndex) streamDuplicates(ctx context.Context, groupKey string) <-chan scanner.Finding {
	out := make(chan scanner.Finding)
	go func() {
		defer close(out)
		_ = i.ForEachDuplicate(ctx, groupKey, func(finding scanner.Finding) error {
			select {
			case out <- finding:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	return out
}

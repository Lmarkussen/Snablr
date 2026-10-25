package output

import (
	"context"
	"fmt"
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

// reportFindingIterator is the bounded handoff between the SQLite-backed
// result store and report consumers. Implementations must not retain a batch
// after visit returns. The legacy slice helper below remains only for
// non-migrated report consumers and is intentionally not used by the scanner
// persistence path itself.
// HTMLReportFindingIterator is the bounded handoff used by disk-backed HTML
// preparation. Implementations must not retain a batch after the visitor
// returns.
type HTMLReportFindingIterator func(context.Context, func(scanner.Finding) error) error

type reportFindingIterator = HTMLReportFindingIterator

var shadowSinks sync.Map

func AttachSQLiteStore(sink scanner.FindingSink, shadow *store.SQLiteStore) {
	if sink == nil || shadow == nil {
		return
	}
	shadowSinks.Store(sink, shadow)
	if attachable, ok := sink.(interface{ AttachSQLiteStore(*store.SQLiteStore) }); ok {
		attachable.AttachSQLiteStore(shadow)
	}
	if wrapped, ok := sink.(*suppressionWriter); ok {
		AttachSQLiteStore(wrapped.inner, shadow)
	}
}

func shadowFinding(sink scanner.FindingSink, finding scanner.Finding) {
	if value, ok := shadowSinks.Load(sink); ok {
		_ = value.(*store.SQLiteStore).RecordFinding(finding)
	}
}

func attachedSQLiteStore(sink scanner.FindingSink) *store.SQLiteStore {
	if value, ok := shadowSinks.Load(sink); ok {
		return value.(*store.SQLiteStore)
	}
	return nil
}

// persistedFindingsForReport switches a writer from live event retention to
// the authoritative SQLite stream when one is attached. The returned slice is
// intentionally scoped to report finalization; callers must still migrate
// correlation/export stages to consume IterateFindings directly before the
// final report itself can be fully streaming.
func persistedFindingsForReport(sink scanner.FindingSink, fallback []scanner.Finding) ([]scanner.Finding, error) {
	shadow := attachedSQLiteStore(sink)
	if shadow == nil {
		return fallback, nil
	}
	iterator, err := persistedReportIterator(shadow)
	if err != nil {
		return nil, err
	}
	findings := make([]scanner.Finding, 0)
	if err := iterator(context.Background(), func(f scanner.Finding) error {
		findings = append(findings, f)
		return nil
	}); err != nil {
		return nil, err
	}
	return findings, nil
}

// persistedReportIterator prepares the derived generation once and returns a
// cursor over the two persisted populations. The cursor decodes only one
// bounded batch at a time and checks cancellation between batches.
func persistedReportIterator(shadow *store.SQLiteStore) (reportFindingIterator, error) {
	return persistedReportIteratorContext(context.Background(), shadow)
}

func persistedReportIteratorContext(ctx context.Context, shadow *store.SQLiteStore) (reportFindingIterator, error) {
	if shadow == nil {
		return nil, fmt.Errorf("SQLite report store is nil")
	}
	if err := shadow.Flush(); err != nil {
		return nil, fmt.Errorf("flush SQLite report state: %w", err)
	}
	ready, err := shadow.CorrelationStateReady(ctx)
	if err != nil {
		return nil, fmt.Errorf("read SQLite correlation publication state: %w", err)
	}
	if !ready {
		if err := persistDiskBackedCorrelations(ctx, shadow); err != nil {
			return nil, fmt.Errorf("persist SQLite-backed correlations: %w", err)
		}
	}
	return func(ctx context.Context, visit func(scanner.Finding) error) error {
		if visit == nil {
			return fmt.Errorf("report finding visitor is nil")
		}
		if err := shadow.IterateFindings(ctx, 256, func(batch []scanner.Finding) error {
			for _, finding := range batch {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := visit(finding); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		return shadow.IterateDerivedFindings(ctx, 256, func(batch []scanner.Finding) error {
			for _, finding := range batch {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := visit(finding); err != nil {
					return err
				}
			}
			return nil
		})
	}, nil
}

func shadowCredential(sink scanner.FindingSink, candidate credentialanalysis.Candidate) {
	if value, ok := shadowSinks.Load(sink); ok {
		_ = value.(*store.SQLiteStore).RecordCredential(candidate)
	}
}

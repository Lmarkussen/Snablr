package credentialanalysis

import "context"

// PersistedAnalysis owns the disk-backed normalization/merge phase. It is a
// bounded replacement for the candidate population portion of Analyze; callers
// choose which records and memberships to consume rather than receiving full
// Confirmed/Review slices.
type PersistedAnalysis struct {
	merger *PersistedMerger
}

func NewPersistedAnalysis() (*PersistedAnalysis, error) {
	merger, err := NewPersistedMerger()
	if err != nil {
		return nil, err
	}
	return &PersistedAnalysis{merger: merger}, nil
}

func (a *PersistedAnalysis) Add(ctx context.Context, candidate Candidate) error {
	if a == nil || a.merger == nil {
		return context.Canceled
	}
	return a.merger.Add(ctx, candidate)
}

func (a *PersistedAnalysis) Stats() PersistedMergeStats {
	if a == nil || a.merger == nil {
		return PersistedMergeStats{}
	}
	return a.merger.Stats()
}

func (a *PersistedAnalysis) IterateRecords(ctx context.Context, visit func(PersistedMergedRecord) error) error {
	if a == nil || a.merger == nil {
		return context.Canceled
	}
	return a.merger.IterateRecords(ctx, visit)
}

func (a *PersistedAnalysis) IterateEvidencePage(ctx context.Context, id int64, cursor EvidenceCursor, limit int, visit func(Evidence) error) (EvidenceCursor, bool, error) {
	if a == nil || a.merger == nil {
		return cursor, false, context.Canceled
	}
	return a.merger.IterateEvidencePage(ctx, id, cursor, limit, visit)
}

func (a *PersistedAnalysis) IterateLocationPage(ctx context.Context, id int64, cursor LocationCursor, limit int, visit func(string) error) (LocationCursor, bool, error) {
	if a == nil || a.merger == nil {
		return cursor, false, context.Canceled
	}
	return a.merger.IterateLocationPage(ctx, id, cursor, limit, visit)
}

func (a *PersistedAnalysis) IterateCorrelations(ctx context.Context, visit func(Correlation) error) error {
	if a == nil || a.merger == nil {
		return context.Canceled
	}
	return a.merger.IterateCorrelations(ctx, visit)
}

func (a *PersistedAnalysis) Close() error {
	if a == nil || a.merger == nil {
		return nil
	}
	return a.merger.Close()
}

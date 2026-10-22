package app

import "snablr/internal/store"

func classifyScanStatus(timedOut, interrupted, persistenceFailed, runFailed bool, completedShares, skippedShares int) store.Status {
	switch {
	case persistenceFailed:
		return store.StatusFailed
	case timedOut:
		return store.StatusTimedOut
	case interrupted:
		return store.StatusInterrupted
	case runFailed && completedShares > 0:
		return store.StatusPartial
	case runFailed:
		return store.StatusFailed
	case skippedShares > 0:
		return store.StatusCompletedWithSkips
	default:
		return store.StatusCompleted
	}
}

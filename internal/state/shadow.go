package state

import "time"

// ShadowStore is deliberately write-only from the authoritative state layer.
// Implementations must never affect resume decisions or make errors fatal.
type ShadowStore interface {
	RecordTarget(host, status string, at time.Time) error
	RecordShare(host, share, status string, at time.Time) error
	RecordFile(key, host, share, path, status, semantics string, size int64, modifiedAt, firstSeen, lastSeen, updatedAt time.Time) error
	RecordAccess(contextID, fileKey, result string, firstSeen, lastSeen time.Time) error
}

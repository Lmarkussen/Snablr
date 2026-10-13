package state

import "time"

// SQLiteStateStore receives logical state transitions for authoritative storage.
type SQLiteStateStore interface {
	RecordTarget(host, status string, at time.Time) error
	RecordShare(host, share, status string, at time.Time) error
	RecordFile(key, host, share, path, status, semantics string, size int64, modifiedAt, firstSeen, lastSeen, updatedAt time.Time) error
	RecordAccess(contextID, fileKey, result string, firstSeen, lastSeen time.Time) error
}

package output

import (
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

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

func shadowCredential(sink scanner.FindingSink, candidate credentialanalysis.Candidate) {
	if value, ok := shadowSinks.Load(sink); ok {
		_ = value.(*store.SQLiteStore).RecordCredential(candidate)
	}
}

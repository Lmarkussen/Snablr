package output

import (
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

var shadowSinks sync.Map

func AttachShadowStore(sink scanner.FindingSink, shadow *store.ShadowStore) {
	if sink == nil || shadow == nil {
		return
	}
	shadowSinks.Store(sink, shadow)
	if wrapped, ok := sink.(*suppressionWriter); ok {
		AttachShadowStore(wrapped.inner, shadow)
	}
}

func shadowFinding(sink scanner.FindingSink, finding scanner.Finding) {
	if value, ok := shadowSinks.Load(sink); ok {
		_ = value.(*store.ShadowStore).RecordFinding(finding)
	}
}

func shadowCredential(sink scanner.FindingSink, candidate credentialanalysis.Candidate) {
	if value, ok := shadowSinks.Load(sink); ok {
		_ = value.(*store.ShadowStore).RecordCredential(candidate)
	}
}

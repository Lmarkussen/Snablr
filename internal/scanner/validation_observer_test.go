package scanner

import (
	"context"
	"sync"
	"testing"

	"snablr/pkg/logx"
)

type recordingValidationObserver struct {
	mu         sync.Mutex
	suppressed int
	visible    int
}

func (r *recordingValidationObserver) RecordSuppressedFinding(SuppressedFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppressed++
}

func (r *recordingValidationObserver) RecordVisibleFinding(Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.visible++
}

func (r *recordingValidationObserver) RecordDowngradedFinding(Finding) {}

// RunScan builds the engine before the output sink exists, so the observer
// handed to NewEngine is nil. Attaching it afterwards must make validation
// mode record findings; previously nothing was ever recorded.
func TestValidationObserverAttachedAfterEngineCreation(t *testing.T) {
	engine := NewEngine(Options{ValidationMode: true}, loadOfficeRules(t), nil, logx.New("error"))
	observer := &recordingValidationObserver{}
	engine.SetValidationObserver(observer)

	content := []byte("[database]\nusername = svc_synthetic\npassword = Synthetic-Valid-9!\n")
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		Host: "fileserver01", Share: "share", FilePath: "app/config.ini", Name: "config.ini",
		Extension: ".ini", Size: int64(len(content)),
	}, content)
	if len(evaluation.Findings) == 0 {
		t.Fatal("fixture produced no findings")
	}
	if observer.visible == 0 {
		t.Fatalf("validation observer recorded no visible findings for %d finding(s)", len(evaluation.Findings))
	}
}

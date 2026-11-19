package output

import (
	"fmt"
	"testing"

	"snablr/internal/diff"
	"snablr/internal/scanner"
)

func selectionTestFindings(from, to int) []scanner.Finding {
	findings := make([]scanner.Finding, 0, to-from)
	for index := from; index < to; index++ {
		finding := sampleFinding()
		finding.FilePath = fmt.Sprintf("synthetic/file-%04d.txt", index)
		findings = append(findings, finding)
	}
	return findings
}

func selectionTestModel() tuiModel {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 100
	model.height = 24
	model.layout()
	return model
}

// The live list keeps only the newest rows. When it is full, each new finding
// drops the oldest row; a selection away from the tail must stay on the same
// finding instead of silently moving to whatever now has its index.
func TestTUILiveSelectionStaysOnFindingWhenListShifts(t *testing.T) {
	model := selectionTestModel()
	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(0, tuiMaxVisibleRows), Status: "running"})
	model.selected = 100
	model.followTail = false
	want := model.findings[100].FilePath

	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(3, tuiMaxVisibleRows+3), Status: "running"})
	if got := model.findings[model.selected].FilePath; got != want {
		t.Fatalf("selection moved to %s, want it to stay on %s", got, want)
	}
	if model.selected != 97 {
		t.Fatalf("selected index=%d, want 97 after three rows dropped", model.selected)
	}
}

// When the selected finding itself drops out of the live list, the selection
// keeps its index as before.
func TestTUILiveSelectionFallsBackWhenFindingDropped(t *testing.T) {
	model := selectionTestModel()
	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(0, tuiMaxVisibleRows), Status: "running"})
	model.selected = 1
	model.followTail = false

	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(5, tuiMaxVisibleRows+5), Status: "running"})
	if model.selected != 1 {
		t.Fatalf("selected index=%d, want 1 when the selected finding is gone", model.selected)
	}
}

// Following the tail is unchanged: the newest finding stays selected.
func TestTUILiveSelectionFollowTailUnchanged(t *testing.T) {
	model := selectionTestModel()
	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(0, 10), Status: "running"})
	model.selected = 9
	model.followTail = true

	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(0, 12), Status: "running"})
	if model.selected != 11 {
		t.Fatalf("selected index=%d, want tail 11", model.selected)
	}
}

// At scan end the live list is replaced by the final list, which can be
// ordered differently. A selection away from the tail stays on its finding.
func TestTUIFinalizeKeepsSelectedFinding(t *testing.T) {
	model := selectionTestModel()
	model.syncLiveState(tuiLiveState{Findings: selectionTestFindings(0, 20), Status: "running"})
	model.selected = 4
	model.followTail = false
	want := model.findings[4].FilePath

	final := selectionTestFindings(0, 30)
	for left, right := 0, len(final)-1; left < right; left, right = left+1, right-1 {
		final[left], final[right] = final[right], final[left]
	}
	updated, _ := model.Update(tuiFinalizeEvent{Findings: final, Performance: &diff.PerformanceSummary{}})
	model = updated.(tuiModel)
	if got := model.findings[model.selected].FilePath; got != want {
		t.Fatalf("finalize moved selection to %s, want %s", got, want)
	}
}

package output

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"

	"snablr/internal/diff"
	"snablr/internal/scanner"
)

func TestTUIFindingRowDoesNotRenderEvidence(t *testing.T) {
	finding := sampleFinding()
	row := renderTUIFindingRow(newTUIFindingRow(finding), 200, false)

	if strings.Contains(row, "ReplaceMe123!") {
		t.Fatalf("finding row leaked matched secret text: %q", row)
	}
	if !strings.Contains(row, "credentials") {
		t.Fatalf("finding row missing category metadata: %q", row)
	}
	if !strings.Contains(row, `\\dc01\SYSVOL\Policies\Groups.xml`) {
		t.Fatalf("finding row missing path metadata: %q", row)
	}
}

func TestTUIDetailRendersMinimalEvidencePane(t *testing.T) {
	finding := sampleArchiveFinding()
	detail := buildTUIDetail(finding)

	for _, expected := range []string{"Path:", "Host / Share:", "Severity:", "Category:", "Evidence:", "web.config"} {
		if !strings.Contains(detail, expected) {
			t.Fatalf("detail pane missing %q:\n%s", expected, detail)
		}
	}
	for _, unwanted := range []string{"Rule:", "Archive:", "Archive member:", "Supporting signals:", "Remediation:"} {
		if strings.Contains(detail, unwanted) {
			t.Fatalf("detail pane should not include %q:\n%s", unwanted, detail)
		}
	}
}

func TestTUIFindingDisplayPathIncludesSQLiteContext(t *testing.T) {
	finding := sampleSQLiteFinding()
	path := findingDisplayPath(finding)

	if !strings.Contains(path, `\\fs01\Apps\Apps\payroll-cache.sqlite3::accounts.password`) {
		t.Fatalf("unexpected sqlite display path: %q", path)
	}
}

func TestTUIFindingRowRespectsWidthBoundaries(t *testing.T) {
	finding := sampleFinding()
	finding.FilePath = strings.Repeat("VeryLongDirectoryName/", 12) + "super_sensitive_configuration_file_name_that_keeps_going.env"
	row := renderTUIFindingRow(newTUIFindingRow(finding), 48, true)

	if width := lipgloss.Width(row); width > 48 {
		t.Fatalf("finding row width exceeded pane width: got %d want <= 48", width)
	}
	if strings.Contains(row, "ReplaceMe123!") {
		t.Fatalf("finding row leaked evidence into metadata pane: %q", row)
	}
}

func TestTUISyncLiveStateKeepsBoundedTail(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		findings:       make([]scanner.Finding, 0, tuiMaxVisibleRows+25),
		status:         "running",
		profile:        "default",
	}
	for idx := 0; idx < tuiMaxVisibleRows+25; idx++ {
		finding := sampleFinding()
		finding.FilePath = "Path/" + strings.Repeat("A", idx%13) + "/" + string(rune('a'+(idx%26)))
		writer.findings = append(writer.findings, finding)
	}

	state := writer.liveState()
	if len(state.Findings) != tuiMaxVisibleRows {
		t.Fatalf("unexpected live finding count: got %d want %d", len(state.Findings), tuiMaxVisibleRows)
	}

	model := newTUIModel(writer)
	model.syncLiveState(state)
	if len(model.findings) != tuiMaxVisibleRows {
		t.Fatalf("model did not keep bounded findings tail: got %d want %d", len(model.findings), tuiMaxVisibleRows)
	}
}

func TestTUILiveStateFiltersSupportingFindings(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
		findings: []scanner.Finding{
			sampleConfigOnlyFinding(),
			sampleWeakScriptFinding(),
			sampleSSHSupportFinding(),
			sampleBackupExtensionFinding(),
			sampleFinding(),
		},
	}

	state := writer.liveState()
	if len(state.Findings) != 1 {
		t.Fatalf("expected only primary live findings, got %#v", state.Findings)
	}
	if state.Findings[0].RuleID != sampleFinding().RuleID {
		t.Fatalf("expected actionable finding to remain visible, got %#v", state.Findings)
	}
}

func TestTUIViewLinesStayWithinTerminalWidth(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 110
	model.height = 22
	model.layout()

	long := sampleFinding()
	long.FilePath = strings.Repeat("Users/Alice/Documents/ExtremelyLongFolderName/", 8) + "sensitive_file_name_that_should_be_clipped.txt"
	model.findings = []scanner.Finding{long, sampleArchiveFinding(), sampleSQLiteFinding()}
	model.selected = 0
	model.ensureSelectionVisible()
	model.refreshDetailContent()

	view := model.View()
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("rendered line exceeded terminal width: got %d want <= %d\n%s", width, model.width, line)
		}
	}
}

func TestTUIViewDoesNotExceedTerminalHeight(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 80
	model.height = 24
	model.layout()

	model.findings = []scanner.Finding{sampleFinding(), sampleArchiveFinding(), sampleSQLiteFinding()}
	model.selected = len(model.findings) - 1
	model.ensureSelectionVisible()
	model.refreshDetailContent()

	view := model.View()
	if lines := len(strings.Split(view, "\n")); lines > model.height {
		t.Fatalf("rendered view exceeded terminal height: got %d want <= %d\n%s", lines, model.height, view)
	}
}

func TestTUIViewLongDetailContentStaysWithinTerminalHeight(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 90
	model.height = 20

	finding := sampleSQLiteFinding()
	finding.FilePath = strings.Repeat("VeryLongDirectoryName/", 10) + "very_long_database_name.sqlite3"
	finding.Snippet = strings.Repeat("token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ", 8)

	model.findings = []scanner.Finding{finding}
	model.selected = 0
	model.layout()
	model.ensureSelectionVisible()

	view := model.View()
	if lines := len(strings.Split(view, "\n")); lines > model.height {
		t.Fatalf("rendered view exceeded terminal height: got %d want <= %d\n%s", lines, model.height, view)
	}
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("rendered line exceeded terminal width: got %d want <= %d\n%s", width, model.width, line)
		}
	}
}

func TestTUISyncLiveStatePreservesManualSelection(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.followTail = false
	model.findings = []scanner.Finding{sampleFinding(), sampleArchiveFinding()}
	model.selected = 0

	state := writer.liveState()
	state.Findings = []scanner.Finding{sampleFinding(), sampleArchiveFinding(), sampleSQLiteFinding()}
	model.syncLiveState(state)

	if model.selected != 0 {
		t.Fatalf("manual selection should remain stable when new findings arrive, got %d", model.selected)
	}
}

func TestTUISelectionStaysWithinVisibleListViewport(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 110
	model.height = 18

	findings := make([]scanner.Finding, 0, 40)
	for i := 0; i < 40; i++ {
		f := sampleFinding()
		f.FilePath = "Path/" + strings.Repeat("x", i%7) + "/" + string(rune('a'+(i%26)))
		findings = append(findings, f)
	}
	model.findings = findings
	model.selected = 0
	model.layout()
	model.ensureSelectionVisible()

	for i := 0; i < 39; i++ {
		model.moveSelection(1)
		if model.selected < model.listPane.YOffset {
			t.Fatalf("selection moved above viewport: selected=%d yOffset=%d", model.selected, model.listPane.YOffset)
		}
		if model.selected >= model.listPane.YOffset+model.listPane.Height {
			t.Fatalf("selection moved below viewport: selected=%d yOffset=%d height=%d", model.selected, model.listPane.YOffset, model.listPane.Height)
		}
	}
}

func TestTUIHandleCtrlCCancelsScanAndQuits(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
		profile:        "default",
	}
	canceled := false
	writer.SetCancelFunc(func() {
		canceled = true
	})

	model := newTUIModel(writer)
	updated, cmd := model.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !canceled {
		t.Fatalf("ctrl+c did not invoke scan cancellation")
	}
	if !writer.WasCanceledByUser() {
		t.Fatalf("writer did not record user cancellation")
	}
	if cmd == nil {
		t.Fatalf("ctrl+c did not return a quit command")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c returned unexpected command message: %#v", msg)
	}
	if updated.(tuiModel).quitHint != "Stopping scan..." {
		t.Fatalf("unexpected quit hint after ctrl+c: %q", updated.(tuiModel).quitHint)
	}
}

func TestTUIFinalizeDoesNotAutoQuit(t *testing.T) {
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

	updated, cmd := model.Update(tuiFinalizeEvent{
		Findings:    []scanner.Finding{sampleFinding()},
		Summary:     summarySnapshot{},
		Performance: &diff.PerformanceSummary{},
		Profile:     "default",
	})
	if cmd != nil {
		t.Fatalf("finalize should not auto-quit the TUI")
	}
	if !updated.(tuiModel).completed {
		t.Fatalf("expected completed state after finalize event")
	}
	if updated.(tuiModel).quitHint != "Scan complete. Press Ctrl-C to close." {
		t.Fatalf("unexpected completion hint: %q", updated.(tuiModel).quitHint)
	}
}

func TestTUIHandleCtrlCAfterCompletionQuitsWithoutCanceling(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "done",
		profile:        "default",
	}
	canceled := false
	writer.SetCancelFunc(func() {
		canceled = true
	})

	model := newTUIModel(writer)
	model.completed = true
	updated, cmd := model.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if canceled {
		t.Fatalf("ctrl+c after completion should not cancel an already-finished scan")
	}
	if cmd == nil {
		t.Fatalf("ctrl+c did not return a quit command")
	}
	msg := cmd()
	if _, ok := msg.(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c returned unexpected command message: %#v", msg)
	}
	if updated.(tuiModel).quitHint != "Closing..." {
		t.Fatalf("unexpected quit hint after completed ctrl+c: %q", updated.(tuiModel).quitHint)
	}
}

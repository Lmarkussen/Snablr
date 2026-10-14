package output

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"snablr/internal/diff"
	"snablr/internal/scanner"
	"snablr/internal/store"
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
	if strings.Contains(row, `\\dc01\SYSVOL\Policies\Groups.xml`) {
		t.Fatalf("finding row should not repeat full path: %q", row)
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

func TestTUIDetailSeparatesEvidenceFromContext(t *testing.T) {
	detail := buildTUIDetail(sampleFinding())
	if !strings.Contains(detail, "Matched text: password = ReplaceMe123!\n\nContext:") {
		t.Fatalf("expected a blank line before Context without losing evidence:\\n%s", detail)
	}
	if !strings.Contains(detail, "Context:\n  user = alice") {
		t.Fatalf("context content was lost:\\n%s", detail)
	}
}

func TestTUIDetailLineMetadataOnlyShowsMeaningfulSourceLines(t *testing.T) {
	withLine := sampleFinding()
	withLine.LineNumber = 47
	withLineDetail := buildTUIDetail(withLine)
	if !strings.Contains(withLineDetail, "Line: 47") {
		t.Fatalf("genuine source line was omitted:\\n%s", withLineDetail)
	}

	lineOne := sampleFinding()
	lineOne.LineNumber = 1
	if !strings.Contains(buildTUIDetail(lineOne), "Line: 1") {
		t.Fatal("genuine source line 1 was omitted")
	}

	structured := sampleFinding()
	structured.RuleID = "dbinspect.infrastructure.dsn"
	structured.SignalType = "validated"
	structured.LineNumber = 0
	structured.MatchedText = "Server=synthetic.invalid;Database=synthetic"
	structured.Context = "Server=synthetic.invalid;Database=synthetic"
	structuredDetail := buildTUIDetail(structured)
	if strings.Contains(structuredDetail, "Line:") {
		t.Fatalf("structured evidence should not show non-applicable line metadata:\\n%s", structuredDetail)
	}
	if !strings.Contains(structuredDetail, "Server=synthetic.invalid") {
		t.Fatalf("structured evidence content was lost:\\n%s", structuredDetail)
	}
}

func TestTUIFindingDisplayPathIncludesSQLiteContext(t *testing.T) {
	finding := sampleSQLiteFinding()
	path := findingDisplayPath(finding)

	if !strings.Contains(path, `\\fileserver01\Apps\Apps\payroll-cache.sqlite3::accounts.password`) {
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

func TestTUIControlFOpensDatabaseSearch(t *testing.T) {
	writer := &TUIWriter{
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		status:         "running",
	}
	model := newTUIModel(writer)
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlF})
	if cmd != nil {
		t.Fatalf("Ctrl-F should not start a blocking command")
	}
	if !updated.(tuiModel).searchOpen {
		t.Fatalf("Ctrl-F did not open search")
	}
}

func TestTUISearchInputAcceptsNavigationLettersAndText(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.searchOpen = true
	model.searchInputActive = true

	for _, value := range []string{"g", "G", "j", "k", "config", "login", "staging", " ", "!", "ø"} {
		for _, character := range []rune(value) {
			updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}})
			model = updated.(tuiModel)
		}
	}
	if model.searchQuery != "gGjkconfigloginstaging !ø" {
		t.Fatalf("search input did not preserve typed query: %q", model.searchQuery)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	model = updated.(tuiModel)
	if model.searchQuery != "gGjkconfigloginstaging !" {
		t.Fatalf("backspace did not remove the last UTF-8 rune: %q", model.searchQuery)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(tuiModel)
	if model.searchOpen {
		t.Fatal("Esc did not close query-entry mode")
	}
}

func TestTUISearchNavigationStartsAfterQueryEntry(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.searchOpen = true
	model.searchInputActive = true
	model.searchResults = []store.SearchResult{
		{Type: store.SearchResultFile, Title: "first"},
		{Type: store.SearchResultFile, Title: "second"},
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	model = updated.(tuiModel)
	if model.searchQuery != "g" || model.searchSelected != 0 {
		t.Fatalf("g was treated as navigation during query entry: query=%q selected=%d", model.searchQuery, model.searchSelected)
	}
	model.searchInputActive = false
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(tuiModel)
	if model.searchSelected != 1 {
		t.Fatalf("G did not navigate results after query entry: selected=%d", model.searchSelected)
	}
}

func TestTUIViewAdvertisesDatabaseSearch(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 100
	model.height = 20
	model.layout()
	if !strings.Contains(model.View(), "Ctrl-F search") {
		t.Fatalf("normal TUI footer does not advertise Ctrl-F search:\n%s", model.View())
	}
}

func TestTUIWrapsLongDetailTokens(t *testing.T) {
	value := strings.Repeat("A", 80)
	wrapped := clampMultiline(value, 20)
	if strings.Contains(wrapped, "...") || len(strings.Split(wrapped, "\n")) < 4 {
		t.Fatalf("long detail token was not hard-wrapped: %q", wrapped)
	}
}

func TestTUISearchCredentialResultIsInformative(t *testing.T) {
	row := formatSearchResult(store.SearchResult{Type: store.SearchResultCredential, Title: "synthetic-user", Context: "password", Detail: "synthetic-user | SyntheticActual482!", Source: "password|synthetic-user|app.config|SyntheticActual482!"})
	for _, expected := range []string{"synthetic-user", "password", "SyntheticActual482!", "app.config"} {
		if !strings.Contains(row, expected) {
			t.Fatalf("credential result missing %q: %s", expected, row)
		}
	}
}

func TestTUISearchViewportFollowsSelection(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 100
	model.height = 12
	model.searchOpen = true
	model.searchResults = make([]store.SearchResult, 100)
	for index := range model.searchResults {
		model.searchResults[index] = store.SearchResult{Type: store.SearchResultFile, Title: fmt.Sprintf("file-%03d.txt", index), Context: "synthetic", Source: "synthetic"}
	}
	for index := 0; index < 99; index++ {
		model.moveSearchSelection(1)
	}
	if model.searchSelected != 99 || model.searchViewport == 0 {
		t.Fatalf("search viewport did not follow selection: selected=%d start=%d", model.searchSelected, model.searchViewport)
	}
	start := model.searchViewport
	model.moveSearchSelection(-99)
	if model.searchSelected != 0 || model.searchViewport != 0 {
		t.Fatalf("search viewport did not return to top: selected=%d start=%d (was %d)", model.searchSelected, model.searchViewport, start)
	}
}

func TestTUIFocusSwitchAndCtrlCRemainDistinct(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	if updated.(tuiModel).focusedPane != tuiPaneDetails {
		t.Fatal("Tab did not move focus to detail pane")
	}
	updated, cmd := updated.(tuiModel).Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil || updated.(tuiModel).quitHint != "Stopping scan..." {
		t.Fatal("Ctrl-C was not routed to scan cancellation")
	}
}

func TestTUIDetailViewportPersistsAcrossRefreshesAndResizes(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 100
	model.height = 16
	model.findings = []scanner.Finding{sampleFinding(), sampleArchiveFinding()}
	model.findings[0].Context = strings.Repeat("synthetic evidence line\n", 40)
	model.selected = 0
	model.followTail = false
	model.layout()
	model.refreshDetailContent(true)

	model.focusedPane = tuiPaneDetails
	for index := 0; index < 4; index++ {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
		model = updated.(tuiModel)
	}
	if model.detailPane.YOffset == 0 {
		t.Fatal("detail viewport did not scroll down")
	}
	offset := model.detailPane.YOffset

	model.syncLiveState(tuiLiveState{Findings: model.findings, Status: "running"})
	if model.detailPane.YOffset != offset {
		t.Fatalf("ordinary scan refresh reset detail viewport: got %d want %d", model.detailPane.YOffset, offset)
	}
	model.refreshDetailContent(false)
	if model.detailPane.YOffset != offset {
		t.Fatalf("same-finding detail refresh reset viewport: got %d want %d", model.detailPane.YOffset, offset)
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	model = updated.(tuiModel)
	if model.detailPane.YOffset <= offset {
		t.Fatalf("PgDn did not advance detail viewport: got %d previous %d", model.detailPane.YOffset, offset)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(tuiModel)
	if model.detailPane.YOffset != model.detailPane.TotalLineCount()-model.detailPane.Height {
		t.Fatalf("G did not move detail viewport to bottom: got %d", model.detailPane.YOffset)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	model = updated.(tuiModel)
	if model.detailPane.YOffset != 0 {
		t.Fatalf("g did not move detail viewport to top: got %d", model.detailPane.YOffset)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	model = updated.(tuiModel)
	beforeResize := model.detailPane.YOffset
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 100, Height: 12})
	model = updated.(tuiModel)
	maxOffset := max(0, model.detailPane.TotalLineCount()-model.detailPane.Height)
	if model.detailPane.YOffset != min(beforeResize, maxOffset) {
		t.Fatalf("resize did not preserve/clamp detail viewport: got %d want %d", model.detailPane.YOffset, min(beforeResize, maxOffset))
	}
	resizedOffset := model.detailPane.YOffset
	updated, _ = model.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
	model = updated.(tuiModel)
	if model.detailPane.YOffset != resizedOffset {
		t.Fatalf("larger resize reset detail viewport: got %d want %d", model.detailPane.YOffset, resizedOffset)
	}

	model.selected = 1
	model.followTail = false
	model.syncLiveState(tuiLiveState{Findings: model.findings, Status: "running"})
	if model.detailPane.YOffset != 0 {
		t.Fatal("changing selected finding did not reset detail viewport")
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
	model.refreshDetailContent(true)

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
	model.refreshDetailContent(true)

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

func TestTUIViewKeepsSingleHeaderAcrossLiveUpdates(t *testing.T) {
	writer := &TUIWriter{
		summary:          newSummaryCollector(),
		validationMode:   newValidationModeCollector(),
		status:           "running",
		profile:          "default",
		targetsTotal:     51,
		targetsProcessed: 41,
		currentHost:      "fileserver01",
	}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 100
	model.height = 20
	model.layout()

	firstView := model.View()
	if strings.Count(firstView, "Snablr Live Scan") != 1 {
		t.Fatalf("expected a single header line in initial view, got:\n%s", firstView)
	}
	for _, line := range strings.Split(firstView, "\n") {
		if width := lipgloss.Width(line); width != model.width {
			t.Fatalf("initial view line width mismatch: got %d want %d\n%s", width, model.width, line)
		}
	}

	writer.targetsProcessed = 42
	writer.currentHost = "fs02"
	model.syncLiveState(writer.liveState())
	secondView := model.View()
	if strings.Count(secondView, "Snablr Live Scan") != 1 {
		t.Fatalf("expected a single header line after live update, got:\n%s", secondView)
	}
	for _, line := range strings.Split(secondView, "\n") {
		if width := lipgloss.Width(line); width != model.width {
			t.Fatalf("updated view line width mismatch: got %d want %d\n%s", width, model.width, line)
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

func TestTUIBookmarkToggleAndBrowser(t *testing.T) {
	state, err := store.Open(t.TempDir()+"/bookmarks.db", store.Options{ScanID: "tui-bookmark", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	if err := state.RecordFile("file-1", "synthetic-host", "SyntheticShare", "lars.txt", "complete", "semantics", 1, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := state.Flush(); err != nil {
		t.Fatal(err)
	}
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running", searchStore: state}
	model := newTUIModel(writer)
	model.findings = []scanner.Finding{{Host: "synthetic-host", Share: "SyntheticShare", FilePath: "lars.txt", Category: "credentials", Severity: "high"}}
	model.selected = 0
	model.windowLoaded = true
	model.width = 100
	model.height = 20
	model.layout()
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlB})
	if cmd == nil {
		t.Fatal("Ctrl-B did not start bookmark toggle")
	}
	model = updated.(tuiModel)
	updated, _ = model.Update(cmd())
	model = updated.(tuiModel)
	if !strings.Contains(model.bookmarkStatus, "Bookmarked") || !strings.Contains(model.View(), "★") {
		t.Fatalf("bookmark feedback/indicator missing: status=%q\n%s", model.bookmarkStatus, model.View())
	}
	selected := model.selected
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyCtrlB})
	model = updated.(tuiModel)
	updated, _ = model.Update(cmd())
	model = updated.(tuiModel)
	if model.selected != selected || !strings.Contains(model.bookmarkStatus, "removed") {
		t.Fatalf("unbookmark changed selection or missed feedback: selected=%d status=%q", model.selected, model.bookmarkStatus)
	}
	updated, cmd = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}, Alt: true})
	model = updated.(tuiModel)
	if !model.bookmarkOpen || cmd == nil {
		t.Fatal("Alt-B did not open bookmark browser")
	}
	updated, _ = model.Update(cmd())
	model = updated.(tuiModel)
	if !strings.Contains(model.View(), "No bookmarks yet") {
		t.Fatalf("empty bookmark state missing:\n%s", model.View())
	}
}

func TestTUIBookmarkViewportFollowsSelection(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.bookmarkOpen = true
	model.width = 100
	model.height = 12
	model.windowLoaded = true
	model.bookmarks = make([]store.Bookmark, 30)
	for index := range model.bookmarks {
		model.bookmarks[index] = store.Bookmark{FileKey: fmt.Sprintf("file-%02d", index), Path: fmt.Sprintf("file-%02d.txt", index), Host: "host", Share: "share"}
	}
	for index := 0; index < 29; index++ {
		updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyDown})
		model = updated.(tuiModel)
	}
	if model.bookmarkSelected != 29 || model.bookmarkViewport == 0 {
		t.Fatalf("bookmark viewport did not follow selection: selected=%d start=%d", model.bookmarkSelected, model.bookmarkViewport)
	}
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	model = updated.(tuiModel)
	if model.bookmarkSelected != 0 || model.bookmarkViewport != 0 {
		t.Fatalf("g did not return bookmark view to top: selected=%d start=%d", model.bookmarkSelected, model.bookmarkViewport)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(tuiModel)
	if model.bookmarkSelected != 29 || model.bookmarkViewport == 0 {
		t.Fatalf("G did not move bookmark view to bottom: selected=%d start=%d", model.bookmarkSelected, model.bookmarkViewport)
	}
}

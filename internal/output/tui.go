package output

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

const (
	tuiRefreshInterval  = 250 * time.Millisecond
	tuiMaxVisibleRows   = 500
	tuiMinSplitWidth    = 100
	tuiMinListWidth     = 36
	tuiMinDetailWidth   = 32
)

type TUIWriter struct {
	w      io.Writer
	closer io.Closer

	mu                  sync.Mutex
	metrics             metrics.Snapshot
	summary             *summaryCollector
	findings            []scanner.Finding
	profile             string
	manifest            string
	suppression         *suppressionSummary
	baselinePerformance *diff.PerformanceSummary
	validationMode      *validationModeCollector
	targetsTotal        int
	targetsProcessed    int
	currentHost         string
	status              string

	events chan tea.Msg
	done   chan struct{}
	runErr error

	cancelMu          sync.Mutex
	cancelScan        context.CancelFunc
	userCanceledScan  bool
}

type tuiFinalizeEvent struct {
	Findings       []scanner.Finding
	Summary        summarySnapshot
	Performance    *diff.PerformanceSummary
	AccessPaths    []accessPathSummary
	Suppression    *suppressionSummary
	ValidationMode *validationModeSummary
	Validation     *validationSummary
	Profile        string
}

type tuiTickMsg struct{}

type tuiLiveState struct {
	Summary          summarySnapshot
	TargetsTotal     int
	TargetsProcessed int
	CurrentHost      string
	Status           string
	Profile          string
	Findings         []scanner.Finding
}

type tuiFindingRow struct {
	Severity    string
	Score       int
	Triage      string
	Category    string
	Path        string
	HasEvidence bool
}

type tuiModel struct {
	writer *TUIWriter

	width  int
	height int

	findings     []scanner.Finding
	selected     int
	followTail   bool
	ready        bool
	completed    bool
	quitHint     string
	live         tuiLiveState
	final        *tuiFinalizeEvent
	listPane     viewport.Model
	detailPane   viewport.Model
	useStacked   bool
	windowLoaded bool

	styles tuiStyles
}

type tuiStyles struct {
	frame        lipgloss.Style
	header       lipgloss.Style
	headerDone   lipgloss.Style
	headerMuted  lipgloss.Style
	pane         lipgloss.Style
	paneBorder   lipgloss.Style
	paneTitle    lipgloss.Style
	selectedRow  lipgloss.Style
	row          lipgloss.Style
	rowMuted     lipgloss.Style
	detailKey    lipgloss.Style
	detailValue  lipgloss.Style
	detailAccent lipgloss.Style
	footer       lipgloss.Style
}

func NewTUIWriter(w io.Writer, closer io.Closer) (*TUIWriter, error) {
	writer := &TUIWriter{
		w:              w,
		closer:         closer,
		summary:        newSummaryCollector(),
		validationMode: newValidationModeCollector(),
		events:         make(chan tea.Msg, 2048),
		done:           make(chan struct{}),
		status:         "running",
	}

	model := newTUIModel(writer)
	program := tea.NewProgram(model, tea.WithOutput(w), tea.WithAltScreen())

	go func() {
		defer close(writer.done)
		_, writer.runErr = program.Run()
	}()

	return writer, nil
}

func (t *TUIWriter) WriteFinding(f scanner.Finding) error {
	t.mu.Lock()
	t.summary.RecordFinding(f)
	t.findings = append(t.findings, f)
	t.mu.Unlock()
	return nil
}

func (t *TUIWriter) RecordHost(host string) {
	t.summary.RecordHost(host)
}

func (t *TUIWriter) RecordShare(host, share string) {
	t.summary.RecordShare(host, share)
}

func (t *TUIWriter) RecordFile(meta scanner.FileMetadata) {
	t.summary.RecordFile(meta)
}

func (t *TUIWriter) RecordSkip(meta scanner.FileMetadata, reason string) {
	t.summary.RecordSkip(meta, reason)
}

func (t *TUIWriter) RecordReadError(meta scanner.FileMetadata, err error) {
	t.summary.RecordReadError(meta, err)
}

func (t *TUIWriter) SetMetricsSnapshot(snapshot metrics.Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.metrics = snapshot
}

func (t *TUIWriter) SetValidationManifest(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.manifest = path
}

func (t *TUIWriter) SetSuppressionSummary(summary *suppressionSummary) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.suppression = summary
}

func (t *TUIWriter) SetScanProfile(profile string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.profile = strings.TrimSpace(profile)
}

func (t *TUIWriter) SetValidationMode(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validationMode.SetEnabled(enabled)
}

func (t *TUIWriter) RecordSuppressedFinding(event scanner.SuppressedFinding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validationMode.RecordSuppressedFinding(event)
}

func (t *TUIWriter) RecordVisibleFinding(f scanner.Finding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validationMode.RecordVisibleFinding(f)
}

func (t *TUIWriter) RecordDowngradedFinding(f scanner.Finding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.validationMode.RecordDowngradedFinding(f)
}

func (t *TUIWriter) SetBaselinePerformance(summary *diff.PerformanceSummary) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if summary == nil {
		t.baselinePerformance = nil
		return
	}
	clone := *summary
	clone.ClassificationDistribution = append([]diff.ClassificationSummary{}, summary.ClassificationDistribution...)
	t.baselinePerformance = &clone
}

func (t *TUIWriter) SetTargetTotal(total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if total < 0 {
		total = 0
	}
	t.targetsTotal = total
}

func (t *TUIWriter) SetCurrentHost(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.currentHost = strings.TrimSpace(host)
}

func (t *TUIWriter) MarkTargetProcessed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targetsProcessed++
}

func (t *TUIWriter) SetStatus(status string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status = strings.TrimSpace(status)
}

func (t *TUIWriter) SetCancelFunc(cancel context.CancelFunc) {
	if t == nil || cancel == nil {
		return
	}
	t.cancelMu.Lock()
	defer t.cancelMu.Unlock()
	t.cancelScan = cancel
}

func (t *TUIWriter) WasCanceledByUser() bool {
	if t == nil {
		return false
	}
	t.cancelMu.Lock()
	defer t.cancelMu.Unlock()
	return t.userCanceledScan
}

func (t *TUIWriter) CancelScan() {
	if t == nil {
		return
	}
	t.cancelMu.Lock()
	cancel := t.cancelScan
	if cancel != nil && !t.userCanceledScan {
		t.userCanceledScan = true
	}
	t.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (t *TUIWriter) Close() error {
	t.mu.Lock()
	augmented := augmentFindingsForReporting(t.findings)
	snapshot := adjustedSummarySnapshot(t.summary.Snapshot(), t.findings, augmented)
	performance := buildPerformanceSummary(snapshot, augmented)
	validationMode := t.validationMode.Summary(snapshot)
	validation, err := buildValidationSummary(t.manifest, augmented)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	final := tuiFinalizeEvent{
		Findings:       cloneFindings(filterPrimaryLiveFindings(augmented)),
		Summary:        snapshot,
		Performance:    &performance,
		AccessPaths:    buildAccessPathSummaries(augmented),
		Suppression:    t.suppression,
		ValidationMode: validationMode,
		Validation:     validation,
		Profile:        strings.TrimSpace(t.profile),
	}
	t.status = "done"
	t.mu.Unlock()

	if t.enqueue(final) {
		<-t.done
	}

	if t.runErr != nil {
		return t.runErr
	}
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}

func (t *TUIWriter) enqueue(msg tea.Msg) bool {
	if t == nil {
		return false
	}
	select {
	case <-t.done:
		return false
	case t.events <- msg:
		return true
	}
}

func (t *TUIWriter) liveState() tuiLiveState {
	t.mu.Lock()
	defer t.mu.Unlock()
	findings := filterPrimaryLiveFindings(t.findings)
	if len(findings) > tuiMaxVisibleRows {
		findings = findings[len(findings)-tuiMaxVisibleRows:]
	}
	return tuiLiveState{
		Summary:          t.summary.LiveSnapshot(),
		TargetsTotal:     t.targetsTotal,
		TargetsProcessed: t.targetsProcessed,
		CurrentHost:      strings.TrimSpace(t.currentHost),
		Status:           strings.TrimSpace(t.status),
		Profile:          strings.TrimSpace(t.profile),
		Findings:         cloneFindings(findings),
	}
}

func newTUIModel(writer *TUIWriter) tuiModel {
	model := tuiModel{
		writer:     writer,
		followTail: true,
		selected:   -1,
		live:       writer.liveState(),
		styles:     defaultTUIStyles(),
	}
	model.listPane = viewport.New(0, 0)
	model.listPane.MouseWheelEnabled = false
	model.listPane.KeyMap = viewport.KeyMap{}
	model.detailPane = viewport.New(0, 0)
	model.detailPane.MouseWheelEnabled = false
	model.detailPane.KeyMap = viewport.KeyMap{}
	return model
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(m.waitForExternalEvent(), m.refreshTick())
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.windowLoaded = true
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		return m, nil
	case tuiFinalizeEvent:
		m.completed = true
		m.final = &msg
		m.findings = cloneFindings(msg.Findings)
		if len(m.findings) == 0 {
			m.selected = -1
		} else if m.selected < 0 || m.selected >= len(m.findings) {
			m.selected = max(0, len(m.findings)-1)
		}
		m.followTail = false
		m.live = m.writer.liveState()
		m.refreshDetailContent()
		m.ensureSelectionVisible()
		m.quitHint = "Scan complete. Press Ctrl-C to close."
		return m, nil
	case tuiTickMsg:
		m.syncLiveState(m.writer.liveState())
		if !m.completed {
			return m, m.refreshTick()
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m tuiModel) View() string {
	if !m.windowLoaded || m.width <= 0 || m.height <= 0 {
		return "Loading scan UI..."
	}

	header := m.renderHeader()
	footer := m.renderFooter()
	bodyHeight := max(3, m.height-lipgloss.Height(header)-lipgloss.Height(footer))
	left, right := m.renderPanes(bodyHeight)

	var body string
	if m.useStacked {
		body = lipgloss.JoinVertical(lipgloss.Left, left, right)
	} else {
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}

	return clampBlock(lipgloss.JoinVertical(lipgloss.Left, header, body, footer), m.width, m.height)
}

func (m tuiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.moveSelection(-1)
	case "down", "j":
		m.moveSelection(1)
	case "pgup", "ctrl+b":
		if m.detailPane.TotalLineCount() > 0 {
			m.detailPane.LineUp(max(1, m.detailPane.Height-2))
		} else {
			m.moveSelection(-max(1, m.listHeight()-1))
		}
	case "pgdown", "ctrl+f":
		if m.detailPane.TotalLineCount() > 0 {
			m.detailPane.LineDown(max(1, m.detailPane.Height-2))
		} else {
			m.moveSelection(max(1, m.listHeight()-1))
		}
	case "g":
		if len(m.findings) > 0 {
			m.selected = 0
			m.followTail = false
			m.ensureSelectionVisible()
			m.refreshDetailContent()
		}
	case "G":
		if len(m.findings) > 0 {
			m.selected = len(m.findings) - 1
			m.followTail = true
			m.ensureSelectionVisible()
			m.refreshDetailContent()
		}
	case "q":
		if m.completed {
			m.quitHint = "Press Ctrl-C to close."
		} else {
			m.quitHint = "Scan is still running. Use Ctrl-C to stop the scan."
		}
	case "ctrl+c":
		if m.writer != nil && !m.completed {
			m.writer.CancelScan()
		}
		if m.completed {
			m.quitHint = "Closing..."
		} else {
			m.quitHint = "Stopping scan..."
		}
		return m, tea.Quit
	}
	return m, nil
}

func (m *tuiModel) waitForExternalEvent() tea.Cmd {
	return func() tea.Msg {
		return <-m.writer.events
	}
}

func (m *tuiModel) refreshTick() tea.Cmd {
	return tea.Tick(tuiRefreshInterval, func(time.Time) tea.Msg {
		return tuiTickMsg{}
	})
}

func (m *tuiModel) moveSelection(delta int) {
	if len(m.findings) == 0 {
		return
	}
	if m.selected < 0 {
		m.selected = 0
	}
	m.selected += delta
	if m.selected < 0 {
		m.selected = 0
	}
	if m.selected >= len(m.findings) {
		m.selected = len(m.findings) - 1
	}
	m.followTail = m.selected == len(m.findings)-1
	m.ensureSelectionVisible()
	m.refreshDetailContent()
}

func (m *tuiModel) syncLiveState(state tuiLiveState) {
	m.live = state
	m.findings = cloneFindings(state.Findings)
	if len(m.findings) == 0 {
		m.selected = -1
		m.listPane.SetContent("")
		m.listPane.GotoTop()
		m.refreshDetailContent()
		return
	}
	if m.selected < 0 {
		m.selected = 0
	}
	if m.followTail {
		m.selected = len(m.findings) - 1
	}
	if m.selected >= len(m.findings) {
		m.selected = len(m.findings) - 1
	}
	m.ensureSelectionVisible()
	m.refreshDetailContent()
}

func (m *tuiModel) ensureSelectionVisible() {
	if len(m.findings) == 0 {
		m.selected = -1
		m.listPane.SetContent("")
		m.listPane.GotoTop()
		return
	}
	if m.selected < 0 {
		m.selected = 0
	}
	visible := max(1, m.listHeight())
	m.refreshListContent()
	if m.selected < m.listPane.YOffset {
		m.listPane.YOffset = m.selected
	}
	if m.selected >= m.listPane.YOffset+visible {
		m.listPane.YOffset = m.selected - visible + 1
	}
	maxOffset := max(0, len(m.findings)-visible)
	if m.listPane.YOffset > maxOffset {
		m.listPane.YOffset = maxOffset
	}
	if m.listPane.YOffset < 0 {
		m.listPane.YOffset = 0
	}
}

func (m *tuiModel) refreshDetailContent() {
	content := m.placeholderDetails()
	if m.selected >= 0 && m.selected < len(m.findings) {
		content = buildTUIDetail(m.findings[m.selected])
	}
	if m.detailPane.Width > 0 {
		content = clampMultiline(content, m.detailPane.Width)
	}
	m.detailPane.SetContent(content)
	m.detailPane.GotoTop()
}

func (m tuiModel) placeholderDetails() string {
	if m.completed && m.final != nil {
		lines := []string{
			"Scan complete.",
			fmt.Sprintf("Profile: %s", valueOrDash(firstNonEmpty(m.final.Profile, m.live.Profile))),
			fmt.Sprintf("Files scanned: %d", m.final.Summary.FilesScanned),
			fmt.Sprintf("Findings: %d", m.final.Summary.MatchesFound),
			fmt.Sprintf("Access paths: %d", len(m.final.AccessPaths)),
		}
		if m.final.Suppression != nil && m.final.Suppression.TotalSuppressed > 0 {
			lines = append(lines, fmt.Sprintf("Suppressed findings: %d", m.final.Suppression.TotalSuppressed))
		}
		lines = append(lines, "", "Select a finding in the left pane to inspect evidence.")
		return strings.Join(lines, "\n")
	}
	return "No finding selected yet.\n\nThe left pane shows finding metadata and scan progress.\nEvidence and matched content appear only here."
}

func (m *tuiModel) layout() {
	m.useStacked = m.width < tuiMinSplitWidth
	_, _, listHeight, detailHeight := m.paneLayout()
	m.listPane.Width = max(10, m.listContentWidth())
	m.listPane.Height = max(1, listHeight)
	m.detailPane.Width = max(10, m.detailContentWidth())
	m.detailPane.Height = max(4, detailHeight)
	m.refreshListContent()
	m.refreshDetailContent()
}

func (m tuiModel) listHeight() int {
	_, _, listHeight, _ := m.paneLayout()
	return max(1, listHeight)
}

func (m tuiModel) renderHeader() string {
	status := firstNonEmpty(m.live.Status, "running")
	elapsed := time.Since(m.live.Summary.StartedAt).Round(time.Second)
	statusText := fmt.Sprintf("Snablr Live Scan  [%s]", strings.ToUpper(status))
	statusLine := m.styles.header.Render(statusText)
	if strings.EqualFold(status, "done") || strings.EqualFold(status, "complete") {
		statusLine = m.styles.headerDone.Render(fmt.Sprintf("Snablr Live Scan  [%s]", "DONE"))
	}
	lines := []string{
		statusLine,
		m.styles.headerMuted.Render(fmt.Sprintf("Profile: %s  Targets: %d/%d  Shares: %d  Files: %d  Primary: %d  Matches: %d  Skipped: %d  Read errors: %d",
			valueOrDash(m.live.Profile),
			m.live.TargetsProcessed,
			m.live.TargetsTotal,
			m.live.Summary.SharesScanned,
			m.live.Summary.FilesScanned,
			len(m.findings),
			m.live.Summary.MatchesFound,
			m.live.Summary.SkippedFiles,
			m.live.Summary.ReadErrors,
		)),
		m.styles.headerMuted.Render(fmt.Sprintf("Host: %s  Elapsed: %s", valueOrDash(m.live.CurrentHost), elapsed)),
	}
	if m.completed && m.final != nil {
		lines = append(lines, m.styles.headerMuted.Render(fmt.Sprintf("Completed. Access paths: %d  Performance: %.2f files/s",
			len(m.final.AccessPaths),
			m.final.Performance.FilesPerSecond,
		)))
	} else {
		lines = append(lines, m.styles.headerMuted.Render("Use up/down or j/k to select findings. Evidence is shown only in the right pane."))
	}
	return clampMultiline(strings.Join(lines, "\n"), m.width)
}

func (m tuiModel) renderFooter() string {
	message := "Controls: up/down or j/k select, g/G jump, PgUp/PgDn scroll details, Ctrl-C cancels, q warns until scan completes"
	if strings.TrimSpace(m.quitHint) != "" {
		message = m.quitHint
	}
	return clampMultiline(m.styles.footer.Render(message), m.width)
}

func (m tuiModel) renderPanes(bodyHeight int) (string, string) {
	if m.useStacked {
		paneWidth := max(20, m.width)
		leftHeight := max(6, bodyHeight/2)
		rightHeight := max(6, bodyHeight-leftHeight)
		left := m.renderListPane(paneWidth, leftHeight)
		right := m.renderDetailPane(paneWidth, rightHeight)
		return left, right
	}

	leftWidth := max(tuiMinListWidth, int(float64(m.width)*0.52))
	rightWidth := max(tuiMinDetailWidth, m.width-leftWidth)
	if leftWidth+rightWidth > m.width {
		rightWidth = m.width - leftWidth
	}
	return m.renderListPane(leftWidth, bodyHeight), m.renderDetailPane(rightWidth, bodyHeight)
}

func (m tuiModel) renderListPane(width, height int) string {
	bodyWidth, bodyHeight := m.paneContentSize(width, height)
	m.listPane.Width = max(10, bodyWidth)
	m.listPane.Height = max(1, bodyHeight-1)
	m.refreshListContent()
	return m.renderBoundedPane("Findings", m.listPane.View(), width, height)
}

func (m tuiModel) renderDetailPane(width, height int) string {
	bodyWidth, bodyHeight := m.paneContentSize(width, height)
	m.detailPane.Width = max(10, bodyWidth)
	m.detailPane.Height = max(4, bodyHeight-1)
	return m.renderBoundedPane("Evidence / Details", m.detailPane.View(), width, height)
}

func (m tuiModel) paneContentSize(outerWidth, outerHeight int) (int, int) {
	frameWidth := m.styles.pane.GetHorizontalFrameSize()
	frameHeight := m.styles.pane.GetVerticalFrameSize()
	return max(1, outerWidth-frameWidth), max(1, outerHeight-frameHeight)
}

func (m tuiModel) paneLayout() (leftWidth, rightWidth, listHeight, detailHeight int) {
	headerHeight := lipgloss.Height(m.renderHeader())
	footerHeight := lipgloss.Height(m.renderFooter())
	bodyHeight := max(3, m.height-headerHeight-footerHeight)

	if m.useStacked {
		_, listBodyHeight := m.paneContentSize(max(20, m.width), max(6, bodyHeight/2))
		_, detailBodyHeight := m.paneContentSize(max(20, m.width), max(6, bodyHeight-max(6, bodyHeight/2)))
		return max(20, m.width), max(20, m.width), max(1, listBodyHeight-1), max(1, detailBodyHeight-1)
	}

	leftWidth = max(tuiMinListWidth, int(float64(m.width)*0.52))
	rightWidth = max(tuiMinDetailWidth, m.width-leftWidth)
	if leftWidth+rightWidth > m.width {
		rightWidth = m.width - leftWidth
	}
	_, listBodyHeight := m.paneContentSize(leftWidth, bodyHeight)
	_, detailBodyHeight := m.paneContentSize(rightWidth, bodyHeight)
	return leftWidth, rightWidth, max(1, listBodyHeight-1), max(1, detailBodyHeight-1)
}

func (m tuiModel) detailContentWidth() int {
	_, rightWidth, _, _ := m.paneLayout()
	if m.useStacked {
		rightWidth = max(20, m.width)
	}
	bodyWidth, _ := m.paneContentSize(rightWidth, max(6, m.height))
	return bodyWidth
}

func (m tuiModel) listContentWidth() int {
	leftWidth, _, _, _ := m.paneLayout()
	if m.useStacked {
		leftWidth = max(20, m.width)
	}
	bodyWidth, _ := m.paneContentSize(leftWidth, max(6, m.height))
	return bodyWidth
}

func (m tuiModel) renderBoundedPane(title, content string, outerWidth, outerHeight int) string {
	if outerWidth <= 1 || outerHeight <= 1 {
		return ""
	}
	border := lipgloss.RoundedBorder()
	innerWidth := max(1, outerWidth-4)
	innerHeight := max(1, outerHeight-2)
	contentHeight := max(0, innerHeight-1)

	titleLine := m.styles.paneTitle.Render(padDisplayWidth(truncateDisplayWidth(title, innerWidth), innerWidth))
	content = clampBlock(content, innerWidth, contentHeight)
	contentLines := strings.Split(content, "\n")
	if len(contentLines) == 1 && contentLines[0] == "" {
		contentLines = contentLines[:0]
	}
	for len(contentLines) < contentHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > contentHeight {
		contentLines = contentLines[:contentHeight]
	}

	lines := make([]string, 0, outerHeight)
	top := border.TopLeft + strings.Repeat(border.Top, max(0, outerWidth-2)) + border.TopRight
	lines = append(lines, m.styles.paneBorder.Render(top))
	lines = append(lines, m.styles.paneBorder.Render(border.Left)+" "+titleLine+" "+m.styles.paneBorder.Render(border.Right))
	for _, line := range contentLines {
		padded := padDisplayWidth(line, innerWidth)
		lines = append(lines, m.styles.paneBorder.Render(border.Left)+" "+padded+" "+m.styles.paneBorder.Render(border.Right))
	}
	bottom := border.BottomLeft + strings.Repeat(border.Bottom, max(0, outerWidth-2)) + border.BottomRight
	lines = append(lines, m.styles.paneBorder.Render(bottom))
	return strings.Join(lines, "\n")
}

func newTUIFindingRow(f scanner.Finding) tuiFindingRow {
	return tuiFindingRow{
		Severity:    strings.ToUpper(valueOrDash(firstNonEmpty(f.Confidence, f.Severity))),
		Score:       f.ConfidenceScore,
		Triage:      firstNonEmpty(displayTriageClass(f.TriageClass), "review"),
		Category:    firstNonEmpty(f.Category, f.RuleName),
		Path:        findingDisplayPath(f),
		HasEvidence: hasTUIEvidence(f),
	}
}

func renderTUIFindingRow(row tuiFindingRow, width int, selected bool) string {
	meta := fmt.Sprintf("[%s", row.Severity)
	if row.Score > 0 {
		meta += fmt.Sprintf(" %d", row.Score)
	}
	meta += "]"
	if row.HasEvidence {
		meta += " *"
	}
	line := fmt.Sprintf("%s %-12s %-18s %s", meta, truncateDisplayWidth(strings.ToUpper(row.Triage), 12), truncateDisplayWidth(row.Category, 18), row.Path)
	line = padDisplayWidth(truncateDisplayWidth(line, max(8, width)), max(8, width))
	style := defaultTUIStyles().row.Copy()
	if selected {
		style = defaultTUIStyles().selectedRow.Copy()
	}
	return style.Render(line)
}

func buildTUIDetail(f scanner.Finding) string {
	lines := []string{
		fmt.Sprintf("Path: %s", findingDisplayPath(f)),
		fmt.Sprintf("Host / Share: %s / %s", valueOrDash(f.Host), valueOrDash(f.Share)),
		fmt.Sprintf("Severity: %s", strings.ToUpper(valueOrDash(firstNonEmpty(f.Confidence, f.Severity)))),
		fmt.Sprintf("Category: %s", valueOrDash(f.Category)),
	}
	evidence := consoleEvidenceLines(f)
	if len(evidence) > 0 {
		lines = append(lines, "", "Evidence:")
		lines = append(lines, evidence...)
	} else {
		lines = append(lines, "", "Evidence:", "No inline evidence captured for this finding.")
	}
	return strings.Join(lines, "\n")
}

func (m *tuiModel) refreshListContent() {
	if m.listPane.Width <= 0 || m.listPane.Height <= 0 {
		return
	}
	if len(m.findings) == 0 {
		message := "No primary findings yet. Supporting observations are retained for reports and correlation."
		m.listPane.SetContent(m.styles.rowMuted.Copy().MaxWidth(m.listPane.Width).Width(m.listPane.Width).Render(message))
		return
	}
	rows := make([]string, 0, len(m.findings))
	for idx := range m.findings {
		rows = append(rows, renderTUIFindingRow(newTUIFindingRow(m.findings[idx]), m.listPane.Width, idx == m.selected))
	}
	m.listPane.SetContent(strings.Join(rows, "\n"))
}

func findingDisplayPath(f scanner.Finding) string {
	switch {
	case strings.TrimSpace(f.FilePath) != "":
		return uncPath(f)
	case strings.TrimSpace(f.ArchivePath) != "":
		return fmt.Sprintf(`\\%s\%s\%s!%s`,
			valueOrDash(f.Host),
			valueOrDash(f.Share),
			strings.ReplaceAll(strings.TrimSpace(f.ArchivePath), "/", `\`),
			strings.ReplaceAll(strings.TrimSpace(f.ArchiveMemberPath), "/", `\`),
		)
	default:
		return uncPath(f)
	}
}

func hasTUIEvidence(f scanner.Finding) bool {
	return len(consoleEvidenceLines(f)) > 0 || strings.TrimSpace(f.MatchReason) != "" || strings.TrimSpace(f.RuleExplanation) != ""
}

func displayTriageClass(value string) string {
	switch strings.TrimSpace(value) {
	case "config-only":
		return "informational"
	case "weak-review":
		return "weak"
	case "":
		return ""
	default:
		return strings.TrimSpace(value)
	}
}

func defaultTUIStyles() tuiStyles {
	return tuiStyles{
		frame:        lipgloss.NewStyle().Padding(0, 1),
		header:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#D7FFE1")),
		headerDone:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7AF0B2")),
		headerMuted:  lipgloss.NewStyle().Foreground(lipgloss.Color("#8EC7A2")),
		pane:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#2F8F5B")).Padding(0, 1),
		paneBorder:   lipgloss.NewStyle().Foreground(lipgloss.Color("#2F8F5B")),
		paneTitle:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#6EE7A8")),
		selectedRow:  lipgloss.NewStyle().Foreground(lipgloss.Color("#F3FFF7")).Background(lipgloss.Color("#1F6F4A")).Bold(true),
		row:          lipgloss.NewStyle().Foreground(lipgloss.Color("#D6F5E3")),
		rowMuted:     lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9E85")),
		detailKey:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7AF0B2")),
		detailValue:  lipgloss.NewStyle().Foreground(lipgloss.Color("#E9FFF2")),
		detailAccent: lipgloss.NewStyle().Foreground(lipgloss.Color("#F4D35E")),
		footer:       lipgloss.NewStyle().Foreground(lipgloss.Color("#7EB894")),
	}
}

func truncateDisplayWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if lipgloss.Width(value) <= width {
		return value
	}
	if width <= 1 {
		return string(runes[:1])
	}
	ellipsis := "…"
	limit := width - lipgloss.Width(ellipsis)
	if limit <= 0 {
		return ellipsis
	}
	var builder strings.Builder
	for _, r := range runes {
		next := builder.String() + string(r)
		if lipgloss.Width(next) > limit {
			break
		}
		builder.WriteRune(r)
	}
	return builder.String() + ellipsis
}

func clampMultiline(value string, width int) string {
	if width <= 0 {
		return ""
	}
	lines := strings.Split(value, "\n")
	for idx, line := range lines {
		if lipgloss.Width(line) <= width {
			continue
		}
		lines[idx] = truncateDisplayWidth(line, width)
	}
	return strings.Join(lines, "\n")
}

func clampBlock(value string, width, height int) string {
	if height <= 0 {
		return clampMultiline(value, width)
	}
	lines := strings.Split(clampMultiline(value, width), "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}

func padDisplayWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	current := lipgloss.Width(value)
	if current >= width {
		return value
	}
	return value + strings.Repeat(" ", width-current)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

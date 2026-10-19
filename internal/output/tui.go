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
	charmansi "github.com/charmbracelet/x/ansi"

	"snablr/internal/diff"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/internal/store"
)

const (
	tuiRefreshInterval = 250 * time.Millisecond
	tuiMaxVisibleRows  = 500
	tuiMinSplitWidth   = 100
	tuiMinListWidth    = 36
	tuiMinDetailWidth  = 32
	tuiSearchPageSize  = 100
)

type tuiPane int

const (
	tuiPaneFindings tuiPane = iota
	tuiPaneDetails
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
	shareScheduler      ShareSchedulerHooks

	events chan tea.Msg
	done   chan struct{}
	runErr error

	cancelMu         sync.Mutex
	cancelScan       context.CancelFunc
	userCanceledScan bool
	searchStore      *store.SQLiteStore
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

type tuiSearchCompletedMsg struct {
	Query   string
	Results []store.SearchResult
	Err     error
}

type tuiBookmarkToggledMsg struct {
	Bookmark   store.Bookmark
	Bookmarked bool
	Err        error
}

type tuiBookmarksLoadedMsg struct {
	Bookmarks []store.Bookmark
	Err       error
}

type tuiBookmarkDetailLoadedMsg struct {
	Details store.BookmarkDetails
	Err     error
}

type tuiLiveState struct {
	Summary          summarySnapshot
	TargetsTotal     int
	TargetsProcessed int
	CurrentHost      string
	Status           string
	Profile          string
	Findings         []scanner.Finding
	ShareQueue       ShareQueueSnapshot
}

type ShareQueueItem struct {
	Host  string
	Share string
	State string
}

type ShareQueueSnapshot struct {
	CurrentHost      string
	CurrentShare     string
	CurrentDirectory string
	DeferredCount    int
	Items            []ShareQueueItem
}

type ShareSchedulerHooks struct {
	DeferCurrent func() string
	SkipFolder   func() string
	SkipShare    func() string
	Snapshot     func() ShareQueueSnapshot
}

type tuiFindingRow struct {
	Severity    string
	Score       int
	Triage      string
	Category    string
	Path        string
	HasEvidence bool
	Bookmarked  bool
}

type tuiModel struct {
	writer *TUIWriter

	width  int
	height int

	findings             []scanner.Finding
	selected             int
	followTail           bool
	ready                bool
	completed            bool
	quitHint             string
	live                 tuiLiveState
	final                *tuiFinalizeEvent
	listPane             viewport.Model
	detailPane           viewport.Model
	useStacked           bool
	windowLoaded         bool
	searchQuery          string
	searchOpen           bool
	searchInputActive    bool
	searchResults        []store.SearchResult
	searchSelected       int
	searchViewport       int
	searchDetail         *store.SearchResult
	searchDetailOffset   int
	searchStatus         string
	focusedPane          tuiPane
	bookmarkedPaths      map[string]bool
	bookmarkedFileKeys   map[string]bool
	bookmarkKeysByPath   map[string]string
	bookmarkOpen         bool
	bookmarks            []store.Bookmark
	bookmarkSelected     int
	bookmarkViewport     int
	bookmarkDetail       *store.BookmarkDetails
	bookmarkDetailOffset int
	bookmarkStatus       string
	queueOpen            bool
	queueSelected        int
	queueViewport        int
	scheduleStatus       string

	styles tuiStyles
}

type tuiStyles struct {
	frame            lipgloss.Style
	header           lipgloss.Style
	headerStatusDone lipgloss.Style
	headerMuted      lipgloss.Style
	pane             lipgloss.Style
	paneBorder       lipgloss.Style
	paneTitle        lipgloss.Style
	paneFocus        lipgloss.Style
	selectedRow      lipgloss.Style
	row              lipgloss.Style
	rowMuted         lipgloss.Style
	detailKey        lipgloss.Style
	detailValue      lipgloss.Style
	detailAccent     lipgloss.Style
	footer           lipgloss.Style
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
	shadowFinding(t, f)
	t.mu.Lock()
	t.summary.RecordFinding(f)
	t.findings = append(t.findings, f)
	t.mu.Unlock()
	return nil
}

func (t *TUIWriter) AttachSQLiteStore(shadow *store.SQLiteStore) {
	t.mu.Lock()
	t.searchStore = shadow
	t.mu.Unlock()
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

func (t *TUIWriter) SetShareScheduler(hooks ShareSchedulerHooks) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.shareScheduler = hooks
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
	queue := ShareQueueSnapshot{}
	if t.shareScheduler.Snapshot != nil {
		queue = t.shareScheduler.Snapshot()
	}
	return tuiLiveState{
		Summary:          t.summary.LiveSnapshot(),
		TargetsTotal:     t.targetsTotal,
		TargetsProcessed: t.targetsProcessed,
		CurrentHost:      strings.TrimSpace(t.currentHost),
		Status:           strings.TrimSpace(t.status),
		Profile:          strings.TrimSpace(t.profile),
		Findings:         cloneFindings(findings),
		ShareQueue:       queue,
	}
}

func newTUIModel(writer *TUIWriter) tuiModel {
	model := tuiModel{
		writer:             writer,
		followTail:         true,
		selected:           -1,
		live:               writer.liveState(),
		styles:             defaultTUIStyles(),
		focusedPane:        tuiPaneFindings,
		bookmarkedPaths:    make(map[string]bool),
		bookmarkedFileKeys: make(map[string]bool),
		bookmarkKeysByPath: make(map[string]string),
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
		m.ensureSearchSelectionVisible()
		m.clampSearchDetailOffset()
		m.ensureBookmarkSelectionVisible()
		m.clampBookmarkDetailOffset()
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
		m.refreshDetailContent(true)
		m.ensureSelectionVisible()
		m.quitHint = "Scan complete. Press Ctrl-C to close."
		return m, nil
	case tuiTickMsg:
		m.syncLiveState(m.writer.liveState())
		if !m.completed {
			return m, m.refreshTick()
		}
		return m, nil
	case tuiSearchCompletedMsg:
		m.searchResults = msg.Results
		m.searchInputActive = len(msg.Results) == 0
		m.searchSelected = 0
		m.searchViewport = 0
		m.searchDetail = nil
		m.searchDetailOffset = 0
		if msg.Err != nil {
			m.searchStatus = "Search failed: " + msg.Err.Error()
		} else if len(msg.Results) == 0 {
			m.searchStatus = "No matches"
		} else {
			m.searchStatus = fmt.Sprintf("%d result(s)", len(msg.Results))
		}
		return m, nil
	case tuiBookmarkToggledMsg:
		if msg.Err != nil {
			m.bookmarkStatus = "Bookmark unavailable: " + msg.Err.Error()
		} else {
			pathKey := bookmarkPathKey(msg.Bookmark.Host, msg.Bookmark.Share, msg.Bookmark.Path)
			m.bookmarkedFileKeys[msg.Bookmark.FileKey] = msg.Bookmarked
			if msg.Bookmarked {
				m.bookmarkKeysByPath[pathKey] = msg.Bookmark.FileKey
				m.bookmarkedPaths[pathKey] = true
			} else {
				delete(m.bookmarkKeysByPath, pathKey)
				delete(m.bookmarkedPaths, pathKey)
			}
			if m.bookmarkOpen && !msg.Bookmarked {
				for index, bookmark := range m.bookmarks {
					if bookmark.FileKey == msg.Bookmark.FileKey {
						m.bookmarks = append(m.bookmarks[:index], m.bookmarks[index+1:]...)
						break
					}
				}
				m.bookmarkDetail = nil
				if len(m.bookmarks) == 0 {
					m.bookmarkSelected, m.bookmarkViewport = 0, 0
				} else if m.bookmarkSelected >= len(m.bookmarks) {
					m.bookmarkSelected = len(m.bookmarks) - 1
					m.ensureBookmarkSelectionVisible()
				}
			}
			if msg.Bookmarked {
				m.bookmarkStatus = "Bookmarked"
			} else {
				m.bookmarkStatus = "Bookmark removed"
			}
			m.refreshListContent()
		}
		return m, nil
	case tuiBookmarksLoadedMsg:
		m.bookmarks = msg.Bookmarks
		m.bookmarkedPaths = make(map[string]bool, len(msg.Bookmarks))
		m.bookmarkedFileKeys = make(map[string]bool, len(msg.Bookmarks))
		m.bookmarkKeysByPath = make(map[string]string, len(msg.Bookmarks))
		m.bookmarkSelected = 0
		m.bookmarkViewport = 0
		m.bookmarkDetail = nil
		if msg.Err != nil {
			m.bookmarkStatus = "Bookmarks unavailable: " + msg.Err.Error()
		} else if len(msg.Bookmarks) == 0 {
			m.bookmarkStatus = "No bookmarks yet. Press Ctrl-D on an interesting file."
		} else {
			m.bookmarkStatus = ""
			for _, bookmark := range msg.Bookmarks {
				pathKey := bookmarkPathKey(bookmark.Host, bookmark.Share, bookmark.Path)
				m.bookmarkedPaths[pathKey] = true
				m.bookmarkedFileKeys[bookmark.FileKey] = true
				m.bookmarkKeysByPath[pathKey] = bookmark.FileKey
			}
		}
		return m, nil
	case tuiBookmarkDetailLoadedMsg:
		if msg.Err != nil {
			m.bookmarkStatus = "Bookmark detail unavailable: " + msg.Err.Error()
		} else {
			m.bookmarkDetail = &msg.Details
			m.bookmarkDetailOffset = 0
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
	if m.bookmarkOpen {
		return m.bookmarkView()
	}
	if m.searchOpen {
		return m.searchView()
	}
	if m.queueOpen {
		header := m.renderHeader()
		footer := m.renderFooter()
		bodyHeight := max(3, m.height-lipgloss.Height(header)-lipgloss.Height(footer))
		body := m.renderQueuePane(m.width, bodyHeight)
		return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, body, footer), m.width, m.height)
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

	return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, body, footer), m.width, m.height)
}

func (m tuiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
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
	if isAltQueueKey(msg) {
		m.searchOpen = false
		m.bookmarkOpen = false
		m.queueOpen = true
		m.queueSelected = 0
		m.queueViewport = 0
		return m, nil
	}
	if m.queueOpen {
		switch msg.String() {
		case "esc":
			m.queueOpen = false
		case "up", "k":
			m.moveQueueSelection(-1)
		case "down", "j":
			m.moveQueueSelection(1)
		case "pgup":
			m.moveQueueSelection(-max(1, m.height-4))
		case "pgdown":
			m.moveQueueSelection(max(1, m.height-4))
		case "g":
			m.queueSelected, m.queueViewport = 0, 0
		case "G":
			m.queueSelected = max(0, len(m.live.ShareQueue.Items)-1)
			m.ensureQueueSelectionVisible()
		}
		return m, nil
	}
	if isAltBookmarkKey(msg) {
		m.searchOpen = false
		m.bookmarkOpen = true
		m.bookmarkStatus = "Loading bookmarks..."
		return m, m.bookmarkListCmd()
	}
	if m.bookmarkOpen {
		return m.handleBookmarkKey(msg)
	}
	if m.searchOpen {
		return m.handleSearchKey(msg)
	}
	if isAltDeferKey(msg) {
		if m.writer == nil {
			m.scheduleStatus = "No active share to defer"
		} else {
			m.writer.mu.Lock()
			hooks := m.writer.shareScheduler
			m.writer.mu.Unlock()
			if hooks.DeferCurrent == nil {
				m.scheduleStatus = "No active share to defer"
			} else {
				m.scheduleStatus = hooks.DeferCurrent()
			}
		}
		return m, nil
	}
	if isAltSkipFolderKey(msg) || isAltSkipShareKey(msg) {
		m.writer.mu.Lock()
		hooks := m.writer.shareScheduler
		m.writer.mu.Unlock()
		if isAltSkipFolderKey(msg) {
			if hooks.SkipFolder == nil {
				m.scheduleStatus = "No active folder to skip"
			} else {
				m.scheduleStatus = hooks.SkipFolder()
			}
		} else if hooks.SkipShare == nil {
			m.scheduleStatus = "No active share to skip"
		} else {
			m.scheduleStatus = hooks.SkipShare()
		}
		return m, nil
	}
	if isCtrlBookmarkKey(msg) {
		if m.selected < 0 || m.selected >= len(m.findings) {
			m.bookmarkStatus = "No file selected"
			return m, nil
		}
		finding := m.findings[m.selected]
		return m, m.toggleFindingBookmarkCmd(finding)
	}
	switch msg.String() {
	case "tab", "shift+tab":
		m.togglePaneFocus()
	case "up", "k":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.LineUp(1)
		} else {
			m.moveSelection(-1)
		}
	case "down", "j":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.LineDown(1)
		} else {
			m.moveSelection(1)
		}
	case "pgup":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.LineUp(max(1, m.detailPane.Height-2))
		} else {
			m.moveSelection(-max(1, m.listHeight()-1))
		}
	case "pgdown":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.LineDown(max(1, m.detailPane.Height-2))
		} else {
			m.moveSelection(max(1, m.listHeight()-1))
		}
	case "g":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.GotoTop()
		} else if len(m.findings) > 0 {
			m.selected = 0
			m.followTail = false
			m.ensureSelectionVisible()
			m.refreshDetailContent(true)
		}
	case "G":
		if m.focusedPane == tuiPaneDetails {
			m.detailPane.GotoBottom()
		} else if len(m.findings) > 0 {
			m.selected = len(m.findings) - 1
			m.followTail = true
			m.ensureSelectionVisible()
			m.refreshDetailContent(true)
		}
	case "q":
		if m.completed {
			m.quitHint = "Press Ctrl-C to close."
		} else {
			m.quitHint = "Scan is still running. Use Ctrl-C to stop the scan."
		}
	case "ctrl+f":
		m.searchOpen = true
		m.searchInputActive = true
		m.searchResults = nil
		m.searchDetail = nil
		m.searchViewport = 0
		m.searchStatus = "Type a query and press Enter"
		m.searchQuery = ""
		return m, nil
	}
	return m, nil
}

func isCtrlBookmarkKey(msg tea.KeyMsg) bool {
	return msg.Type == tea.KeyCtrlD || msg.String() == "ctrl+d"
}

func isAltBookmarkKey(msg tea.KeyMsg) bool {
	if !msg.Alt || msg.Type != tea.KeyRunes || len(msg.Runes) != 1 {
		return false
	}
	return msg.Runes[0] == 'd' || msg.Runes[0] == 'D'
}

func isAltQueueKey(msg tea.KeyMsg) bool {
	return isAltRuneKey(msg, 'q')
}

func isAltDeferKey(msg tea.KeyMsg) bool {
	return isAltRuneKey(msg, 'l')
}

func isAltSkipFolderKey(msg tea.KeyMsg) bool {
	return isAltRuneKey(msg, 'k')
}

func isAltSkipShareKey(msg tea.KeyMsg) bool {
	return isAltRuneKey(msg, 's')
}

func isAltRuneKey(msg tea.KeyMsg, expected rune) bool {
	if !msg.Alt || msg.Type != tea.KeyRunes || len(msg.Runes) != 1 {
		return false
	}
	return msg.Runes[0] == expected || msg.Runes[0] == expected-('a'-'A')
}

func bookmarkPathKey(host, share, path string) string {
	return host + "\x00" + share + "\x00" + path
}

func (m tuiModel) bookmarkStore() *store.SQLiteStore {
	if m.writer == nil {
		return nil
	}
	m.writer.mu.Lock()
	defer m.writer.mu.Unlock()
	return m.writer.searchStore
}

func (m tuiModel) toggleFindingBookmarkCmd(finding scanner.Finding) tea.Cmd {
	writer := m.writer
	return func() tea.Msg {
		if writer == nil {
			return tuiBookmarkToggledMsg{Err: fmt.Errorf("bookmark store is unavailable")}
		}
		writer.mu.Lock()
		bookmarkStore := writer.searchStore
		writer.mu.Unlock()
		if bookmarkStore == nil {
			return tuiBookmarkToggledMsg{Err: fmt.Errorf("authoritative SQLite store is unavailable")}
		}
		bookmark, bookmarked, err := bookmarkStore.ToggleBookmark(context.Background(), finding.Host, finding.Share, finding.FilePath)
		return tuiBookmarkToggledMsg{Bookmark: bookmark, Bookmarked: bookmarked, Err: err}
	}
}

func (m tuiModel) toggleBookmarkKeyCmd(key string) tea.Cmd {
	writer := m.writer
	return func() tea.Msg {
		if writer == nil {
			return tuiBookmarkToggledMsg{Err: fmt.Errorf("bookmark store is unavailable")}
		}
		writer.mu.Lock()
		bookmarkStore := writer.searchStore
		writer.mu.Unlock()
		if bookmarkStore == nil {
			return tuiBookmarkToggledMsg{Err: fmt.Errorf("authoritative SQLite store is unavailable")}
		}
		bookmark, bookmarked, err := bookmarkStore.ToggleBookmarkKey(context.Background(), key)
		return tuiBookmarkToggledMsg{Bookmark: bookmark, Bookmarked: bookmarked, Err: err}
	}
}

func (m tuiModel) bookmarkListCmd() tea.Cmd {
	writer := m.writer
	return func() tea.Msg {
		if writer == nil {
			return tuiBookmarksLoadedMsg{Err: fmt.Errorf("bookmark store is unavailable")}
		}
		writer.mu.Lock()
		bookmarkStore := writer.searchStore
		writer.mu.Unlock()
		if bookmarkStore == nil {
			return tuiBookmarksLoadedMsg{Err: fmt.Errorf("authoritative SQLite store is unavailable")}
		}
		bookmarks, err := bookmarkStore.ListBookmarks(context.Background(), tuiSearchPageSize, 0)
		return tuiBookmarksLoadedMsg{Bookmarks: bookmarks, Err: err}
	}
}

func (m tuiModel) bookmarkDetailCmd(key string) tea.Cmd {
	writer := m.writer
	return func() tea.Msg {
		if writer == nil {
			return tuiBookmarkDetailLoadedMsg{Err: fmt.Errorf("bookmark store is unavailable")}
		}
		writer.mu.Lock()
		bookmarkStore := writer.searchStore
		writer.mu.Unlock()
		if bookmarkStore == nil {
			return tuiBookmarkDetailLoadedMsg{Err: fmt.Errorf("authoritative SQLite store is unavailable")}
		}
		details, err := bookmarkStore.BookmarkDetails(context.Background(), key)
		return tuiBookmarkDetailLoadedMsg{Details: details, Err: err}
	}
}

func (m tuiModel) handleBookmarkKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.bookmarkDetail != nil {
		switch msg.String() {
		case "esc":
			m.bookmarkDetail = nil
			m.bookmarkDetailOffset = 0
		case "ctrl+d":
			return m, m.toggleBookmarkKeyCmd(m.bookmarkDetail.Bookmark.FileKey)
		case "up", "k":
			m.bookmarkDetailOffset = max(0, m.bookmarkDetailOffset-1)
		case "down", "j":
			m.bookmarkDetailOffset++
		case "pgup":
			m.bookmarkDetailOffset = max(0, m.bookmarkDetailOffset-m.bookmarkDetailVisibleRows())
		case "pgdown":
			m.bookmarkDetailOffset += m.bookmarkDetailVisibleRows()
		case "g":
			m.bookmarkDetailOffset = 0
		case "G":
			m.bookmarkDetailOffset = 1 << 30
		}
		m.clampBookmarkDetailOffset()
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.bookmarkOpen = false
		m.bookmarkStatus = ""
	case "enter":
		if len(m.bookmarks) > 0 {
			m.bookmarkStatus = "Loading bookmark detail..."
			return m, m.bookmarkDetailCmd(m.bookmarks[m.bookmarkSelected].FileKey)
		}
	case "ctrl+d":
		if len(m.bookmarks) > 0 {
			return m, m.toggleBookmarkKeyCmd(m.bookmarks[m.bookmarkSelected].FileKey)
		}
	case "up", "k":
		m.moveBookmarkSelection(-1)
	case "down", "j":
		m.moveBookmarkSelection(1)
	case "pgup":
		m.moveBookmarkSelection(-m.bookmarkVisibleRows())
	case "pgdown":
		m.moveBookmarkSelection(m.bookmarkVisibleRows())
	case "g":
		m.bookmarkSelected = 0
		m.bookmarkViewport = 0
	case "G":
		m.bookmarkSelected = max(0, len(m.bookmarks)-1)
		m.ensureBookmarkSelectionVisible()
	}
	return m, nil
}

func (m *tuiModel) moveBookmarkSelection(delta int) {
	if len(m.bookmarks) == 0 {
		return
	}
	m.bookmarkSelected = max(0, min(len(m.bookmarks)-1, m.bookmarkSelected+delta))
	m.ensureBookmarkSelectionVisible()
}

func (m *tuiModel) bookmarkVisibleRows() int { return max(1, m.height-8) }

func (m *tuiModel) ensureBookmarkSelectionVisible() {
	visible := m.bookmarkVisibleRows()
	if m.bookmarkSelected < m.bookmarkViewport {
		m.bookmarkViewport = m.bookmarkSelected
	}
	if m.bookmarkSelected >= m.bookmarkViewport+visible {
		m.bookmarkViewport = m.bookmarkSelected - visible + 1
	}
	maxStart := max(0, len(m.bookmarks)-visible)
	m.bookmarkViewport = max(0, min(m.bookmarkViewport, maxStart))
}

func (m *tuiModel) bookmarkDetailVisibleRows() int { return detailViewportVisibleRows(m.height) }

func (m *tuiModel) clampBookmarkDetailOffset() {
	if m.bookmarkDetail == nil {
		m.bookmarkDetailOffset = 0
		return
	}
	lines := detailViewportLines(m.bookmarkDetailContent(), detailViewportWidth(m.width))
	m.bookmarkDetailOffset = max(0, min(m.bookmarkDetailOffset, max(0, len(lines)-m.bookmarkDetailVisibleRows())))
}

func detailViewportWidth(outerWidth int) int {
	return max(1, outerWidth-4)
}

func detailViewportVisibleRows(height int) int {
	return max(1, height-5)
}

func detailViewportLines(content string, width int) []string {
	return strings.Split(clampMultiline(content, max(1, width)), "\n")
}

func detailViewport(content string, width, visible, offset int) (string, int) {
	lines := detailViewportLines(content, width)
	visible = max(1, visible)
	offset = max(0, min(offset, max(0, len(lines)-visible)))
	end := min(len(lines), offset+visible)
	return strings.Join(lines[offset:end], "\n"), offset
}

func (m *tuiModel) togglePaneFocus() {
	if m.focusedPane == tuiPaneFindings {
		m.focusedPane = tuiPaneDetails
	} else {
		m.focusedPane = tuiPaneFindings
	}
}

func (m tuiModel) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searchDetail != nil {
		switch msg.String() {
		case "esc":
			m.searchDetail = nil
			m.searchDetailOffset = 0
		case "up", "k":
			m.searchDetailOffset = max(0, m.searchDetailOffset-1)
		case "down", "j":
			m.searchDetailOffset++
		case "pgup":
			m.searchDetailOffset = max(0, m.searchDetailOffset-m.searchDetailVisibleRows())
		case "pgdown":
			m.searchDetailOffset += m.searchDetailVisibleRows()
		case "g":
			m.searchDetailOffset = 0
		case "G":
			m.searchDetailOffset = 1 << 30
		case "ctrl+d":
			if m.searchDetail.BookmarkKey == "" {
				m.searchStatus = "This search result has no bookmarkable file"
				return m, nil
			}
			return m, m.toggleBookmarkKeyCmd(m.searchDetail.BookmarkKey)
		}
		m.clampSearchDetailOffset()
		return m, nil
	}
	if m.searchInputActive {
		switch msg.String() {
		case "esc":
			m.searchOpen = false
			return m, nil
		case "enter":
			query := strings.TrimSpace(m.searchQuery)
			if query == "" {
				m.searchStatus = "Enter a search query"
				return m, nil
			}
			m.searchInputActive = false
			m.searchStatus = "Searching..."
			return m, m.searchCmd(query)
		case "backspace":
			runes := []rune(m.searchQuery)
			if len(runes) > 0 {
				m.searchQuery = string(runes[:len(runes)-1])
			}
			return m, nil
		}
		if len(msg.Runes) > 0 && len([]rune(m.searchQuery))+len(msg.Runes) <= 256 {
			m.searchQuery += string(msg.Runes)
		}
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.searchOpen = false
		return m, nil
	case "enter":
		if len(m.searchResults) > 0 {
			m.searchDetail = &m.searchResults[m.searchSelected]
			m.searchDetailOffset = 0
			return m, nil
		}
		query := strings.TrimSpace(m.searchQuery)
		if query == "" {
			m.searchStatus = "Enter a search query"
			return m, nil
		}
		m.searchStatus = "Searching..."
		return m, m.searchCmd(query)
	case "ctrl+d":
		if len(m.searchResults) == 0 || m.searchResults[m.searchSelected].BookmarkKey == "" {
			m.searchStatus = "This search result has no bookmarkable file"
			return m, nil
		}
		return m, m.toggleBookmarkKeyCmd(m.searchResults[m.searchSelected].BookmarkKey)
	case "up", "k", "ctrl+p":
		m.moveSearchSelection(-1)
	case "down", "j", "ctrl+n":
		m.moveSearchSelection(1)
	case "pgup":
		m.moveSearchSelection(-m.searchResultVisibleRows())
	case "pgdown":
		m.moveSearchSelection(m.searchResultVisibleRows())
	case "g":
		m.searchSelected = 0
		m.searchViewport = 0
	case "G":
		m.searchSelected = max(0, len(m.searchResults)-1)
		m.ensureSearchSelectionVisible()
	default:
		if msg.String() == "backspace" {
			runes := []rune(m.searchQuery)
			if len(runes) > 0 {
				m.searchQuery = string(runes[:len(runes)-1])
			}
			return m, nil
		}
		if len(msg.Runes) > 0 && len([]rune(m.searchQuery))+len(msg.Runes) <= 256 {
			m.searchQuery += string(msg.Runes)
		}
		return m, nil
	}
	return m, nil
}

func (m *tuiModel) moveSearchSelection(delta int) {
	if len(m.searchResults) == 0 {
		return
	}
	m.searchSelected = max(0, min(len(m.searchResults)-1, m.searchSelected+delta))
	m.ensureSearchSelectionVisible()
}

func (m *tuiModel) searchResultVisibleRows() int {
	return max(1, m.height-8)
}

func (m *tuiModel) searchDetailVisibleRows() int {
	return detailViewportVisibleRows(m.height)
}

func (m *tuiModel) clampSearchDetailOffset() {
	if m.searchDetail == nil {
		m.searchDetailOffset = 0
		return
	}
	lines := detailViewportLines(m.searchDetailContent(), detailViewportWidth(m.width))
	maxOffset := max(0, len(lines)-m.searchDetailVisibleRows())
	m.searchDetailOffset = max(0, min(m.searchDetailOffset, maxOffset))
}

func (m *tuiModel) ensureSearchSelectionVisible() {
	visible := m.searchResultVisibleRows()
	if m.searchSelected < m.searchViewport {
		m.searchViewport = m.searchSelected
	}
	if m.searchSelected >= m.searchViewport+visible {
		m.searchViewport = m.searchSelected - visible + 1
	}
	maxStart := max(0, len(m.searchResults)-visible)
	m.searchViewport = max(0, min(m.searchViewport, maxStart))
}

func (m tuiModel) searchCmd(query string) tea.Cmd {
	writer := m.writer
	return func() tea.Msg {
		if writer == nil {
			return tuiSearchCompletedMsg{Query: query, Err: fmt.Errorf("search is unavailable")}
		}
		writer.mu.Lock()
		searchStore := writer.searchStore
		writer.mu.Unlock()
		if searchStore == nil {
			return tuiSearchCompletedMsg{Query: query, Err: fmt.Errorf("authoritative SQLite store is unavailable")}
		}
		results, err := searchStore.Search(context.Background(), query, store.SearchOptions{Limit: tuiSearchPageSize})
		return tuiSearchCompletedMsg{Query: query, Results: results, Err: err}
	}
}

func (m tuiModel) searchView() string {
	header := m.styles.header.Render("Snablr Search")
	footer := m.styles.footer.Render("Enter search/open • ↑/↓ move • PgUp/PgDn • g/G • Esc back/close")
	if m.searchDetail != nil {
		body, offset := detailViewport(m.searchDetailContent(), detailViewportWidth(m.width), m.searchDetailVisibleRows(), m.searchDetailOffset)
		m.searchDetailOffset = offset
		return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, m.renderBoundedPane("Search Result", body, m.width, max(3, m.height-2)), footer), m.width, m.height)
	}
	lines := []string{"Search: " + m.searchQuery, "", m.searchStatus}
	visible := m.searchResultVisibleRows()
	maxStart := max(0, len(m.searchResults)-visible)
	start := max(0, min(m.searchViewport, maxStart))
	end := min(len(m.searchResults), start+visible)
	for idx := start; idx < end; idx++ {
		result := m.searchResults[idx]
		prefix := "  "
		if idx == m.searchSelected {
			prefix = "> "
		}
		line := prefix + formatSearchResult(result)
		if result.BookmarkKey != "" && m.bookmarkedPathsForResult(result) {
			line = prefix + "★ " + formatSearchResult(result)
		}
		lines = append(lines, truncateDisplayWidth(line, max(1, m.width-4)))
	}
	body := strings.Join(lines, "\n")
	return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, m.renderBoundedPane("Database Search", body, m.width, max(3, m.height-2)), footer), m.width, m.height)
}

func (m tuiModel) bookmarkView() string {
	header := m.styles.header.Render(fmt.Sprintf("Bookmarks  %d", len(m.bookmarks)))
	footer := m.styles.footer.Render("Enter open • ↑/↓ or j/k move • PgUp/PgDn • g/G • Ctrl-D remove • Esc back")
	if m.bookmarkDetail != nil {
		body, offset := detailViewport(m.bookmarkDetailContent(), detailViewportWidth(m.width), m.bookmarkDetailVisibleRows(), m.bookmarkDetailOffset)
		m.bookmarkDetailOffset = offset
		return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, m.renderBoundedPane("Bookmark Detail", body, m.width, max(3, m.height-2)), footer), m.width, m.height)
	}
	lines := []string{"Select a bookmarked file to inspect its findings and credentials."}
	if len(m.bookmarks) == 0 {
		lines = []string{"No bookmarks yet.", "Press Ctrl-D on an interesting file to bookmark it."}
	} else {
		visible := m.bookmarkVisibleRows()
		start := max(0, min(m.bookmarkViewport, max(0, len(m.bookmarks)-visible)))
		end := min(len(m.bookmarks), start+visible)
		for index := start; index < end; index++ {
			bookmark := m.bookmarks[index]
			prefix := "  "
			if index == m.bookmarkSelected {
				prefix = "> "
			}
			line := fmt.Sprintf("%s[FILE] %s | %s / %s", prefix, pathLeaf(bookmark.Path), valueOrDash(bookmark.Host), valueOrDash(bookmark.Share))
			lines = append(lines, truncateDisplayWidth(line, max(1, m.width-4)))
		}
	}
	if strings.TrimSpace(m.bookmarkStatus) != "" {
		lines = append([]string{m.bookmarkStatus, ""}, lines...)
	}
	return fitScreenBlock(lipgloss.JoinVertical(lipgloss.Left, header, m.renderBoundedPane("Bookmarked Files", strings.Join(lines, "\n"), m.width, max(3, m.height-2)), footer), m.width, m.height)
}

func pathLeaf(path string) string {
	path = strings.TrimRight(strings.ReplaceAll(path, "\\", "/"), "/")
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[index+1:]
	}
	return path
}

func (m tuiModel) bookmarkDetailContent() string {
	if m.bookmarkDetail == nil {
		return ""
	}
	detail := m.bookmarkDetail
	lines := []string{
		"Path: " + valueOrDash(detail.Bookmark.Path),
		"Host / Share: " + valueOrDash(detail.Bookmark.Host) + " / " + valueOrDash(detail.Bookmark.Share),
		"File identity: " + valueOrDash(detail.Bookmark.FileKey),
		"",
		fmt.Sprintf("Related findings: %d", len(detail.Findings)),
	}
	for _, finding := range detail.Findings {
		lines = append(lines, fmt.Sprintf("- %s | %s | %s", valueOrDash(finding.RuleID), valueOrDash(finding.Category), strings.ToUpper(valueOrDash(firstNonEmpty(finding.Confidence, finding.Severity)))))
		for _, evidence := range consoleEvidenceLines(finding) {
			lines = append(lines, "  "+evidence)
		}
	}
	lines = append(lines, "", fmt.Sprintf("Credentials: %d", len(detail.Credentials)))
	for _, credential := range detail.Credentials {
		lines = append(lines, fmt.Sprintf("- %s | %s | %s", valueOrDash(credential.Identity), valueOrDash(credential.Type), valueOrDash(credential.Value)))
	}
	return strings.Join(lines, "\n")
}

func (m tuiModel) searchDetailContent() string {
	result := m.searchDetail
	return strings.Join([]string{
		"Type: " + string(result.Type),
		"Title: " + valueOrDash(result.Title),
		"Context: " + valueOrDash(result.Context),
		"Source: " + valueOrDash(result.Source),
		"Detail: " + valueOrDash(result.Detail),
		"",
		"Esc returns to results.",
	}, "\n")
}

func formatSearchResult(result store.SearchResult) string {
	switch result.Type {
	case store.SearchResultFile:
		return fmt.Sprintf("[FILE] %s | %s | %s", valueOrDash(result.Title), valueOrDash(result.Context), valueOrDash(result.Source))
	case store.SearchResultFinding:
		return fmt.Sprintf("[FINDING] %s | %s | %s", valueOrDash(result.Title), valueOrDash(result.Source), valueOrDash(result.Context))
	case store.SearchResultCredential:
		return fmt.Sprintf("[CREDENTIAL] %s | %s | %s | %s", valueOrDash(result.Title), valueOrDash(result.Context), valueOrDash(result.Detail), compactCredentialSource(result.Source))
	case store.SearchResultEvidence:
		return fmt.Sprintf("[EVIDENCE] %s | %s | %s", valueOrDash(result.Title), valueOrDash(result.Source), valueOrDash(result.Detail))
	default:
		return fmt.Sprintf("[%s] %s | %s", result.Type, valueOrDash(result.Title), valueOrDash(result.Detail))
	}
}

func compactCredentialSource(source string) string {
	parts := strings.SplitN(source, "|", 4)
	if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
		return parts[2]
	}
	return source
}

func (m tuiModel) bookmarkedPathsForResult(result store.SearchResult) bool {
	for _, bookmark := range m.bookmarks {
		if bookmark.FileKey == result.BookmarkKey {
			return true
		}
	}
	return false
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
	m.refreshDetailContent(true)
}

func (m *tuiModel) syncLiveState(state tuiLiveState) {
	previousSelected := m.selected
	m.live = state
	if len(m.live.ShareQueue.Items) == 0 {
		m.queueSelected, m.queueViewport = 0, 0
	} else {
		m.queueSelected = max(0, min(m.queueSelected, len(m.live.ShareQueue.Items)-1))
		m.ensureQueueSelectionVisible()
	}
	m.findings = cloneFindings(state.Findings)
	if len(m.findings) == 0 {
		m.selected = -1
		m.listPane.SetContent("")
		m.listPane.GotoTop()
		m.refreshDetailContent(true)
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
	m.refreshDetailContent(previousSelected != m.selected)
}

func (m *tuiModel) ensureQueueSelectionVisible() {
	visible := max(1, m.height-4)
	if m.queueSelected < m.queueViewport {
		m.queueViewport = m.queueSelected
	}
	if m.queueSelected >= m.queueViewport+visible {
		m.queueViewport = m.queueSelected - visible + 1
	}
	m.queueViewport = max(0, min(m.queueViewport, max(0, len(m.live.ShareQueue.Items)-visible)))
}

func (m *tuiModel) moveQueueSelection(delta int) {
	if len(m.live.ShareQueue.Items) == 0 {
		return
	}
	m.queueSelected = max(0, min(len(m.live.ShareQueue.Items)-1, m.queueSelected+delta))
	m.ensureQueueSelectionVisible()
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

func (m *tuiModel) refreshDetailContent(resetViewport bool) {
	offset := m.detailPane.YOffset
	content := m.placeholderDetails()
	if m.selected >= 0 && m.selected < len(m.findings) {
		content = buildTUIDetail(m.findings[m.selected])
	}
	if m.detailPane.Width > 0 {
		content = clampMultiline(content, m.detailPane.Width)
	}
	m.detailPane.SetContent(content)
	if resetViewport {
		offset = 0
	}
	maxOffset := max(0, m.detailPane.TotalLineCount()-m.detailPane.Height)
	m.detailPane.YOffset = max(0, min(offset, maxOffset))
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
	m.refreshDetailContent(false)
}

func (m tuiModel) listHeight() int {
	_, _, listHeight, _ := m.paneLayout()
	return max(1, listHeight)
}

func (m tuiModel) renderHeader() string {
	status := firstNonEmpty(m.live.Status, "running")
	elapsed := time.Since(m.live.Summary.StartedAt).Round(time.Second)
	statusText := fmt.Sprintf("Snablr Live Scan  [%s]", strings.ToUpper(status))
	if strings.EqualFold(status, "done") || strings.EqualFold(status, "complete") {
		statusText = "Snablr Live Scan  [" + m.styles.headerStatusDone.Render("DONE") + "]"
	}
	statusLine := m.styles.header.Render(statusText)
	lines := []string{
		statusLine,
		m.styles.headerMuted.Render(fmt.Sprintf("Profile: %s  Targets: %d/%d  Shares: %d  Files: %d  Matches: %d  Read errors: %d",
			valueOrDash(m.live.Profile),
			m.live.TargetsProcessed,
			m.live.TargetsTotal,
			m.live.Summary.SharesScanned,
			m.live.Summary.FilesScanned,
			m.live.Summary.MatchesFound,
			m.live.Summary.ReadErrors,
		)),
		m.styles.headerMuted.Render(fmt.Sprintf("Host: %s  Elapsed: %s", valueOrDash(m.live.CurrentHost), elapsed)),
	}
	if current := strings.TrimSpace(m.live.ShareQueue.CurrentShare); current != "" {
		lines = append(lines, m.styles.headerMuted.Render(fmt.Sprintf("Current share: \\\\%s\\%s  Deferred: %d", m.live.ShareQueue.CurrentHost, current, m.live.ShareQueue.DeferredCount)))
	}
	if directory := strings.TrimSpace(m.live.ShareQueue.CurrentDirectory); directory != "" {
		lines = append(lines, m.styles.headerMuted.Render(fmt.Sprintf("Current folder: \\\\%s\\%s\\%s", m.live.ShareQueue.CurrentHost, m.live.ShareQueue.CurrentShare, directory)))
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
	message := "Tab switch pane • Ctrl-F search • Ctrl-D bookmark • Alt-D bookmarks • Ctrl-C stop\nAlt-K skip folder • Alt-S skip share • Alt-L defer • Alt-Q queue"
	if m.queueOpen {
		message = "↑/↓ or j/k move • PgUp/PgDn page • g/G top/bottom • Esc back"
	}
	if strings.TrimSpace(m.scheduleStatus) != "" {
		message = m.scheduleStatus + " • " + message
	}
	if strings.TrimSpace(m.bookmarkStatus) != "" {
		message = m.bookmarkStatus + " • " + message
	}
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

func (m tuiModel) renderQueuePane(width, height int) string {
	visible := max(1, height-4)
	start := max(0, min(m.queueViewport, max(0, len(m.live.ShareQueue.Items)-visible)))
	end := min(len(m.live.ShareQueue.Items), start+visible)
	lines := make([]string, 0, end-start+1)
	for index := start; index < end; index++ {
		item := m.live.ShareQueue.Items[index]
		marker := "  "
		if index == m.queueSelected {
			marker = "> "
		}
		lines = append(lines, fmt.Sprintf("%s[%s] \\\\%s\\%s", marker, strings.ToUpper(item.State), item.Host, item.Share))
	}
	if len(lines) == 0 {
		lines = append(lines, "No share queue is available.")
	}
	return m.renderBoundedPane(fmt.Sprintf("Share Queue  (%d deferred)", m.live.ShareQueue.DeferredCount), strings.Join(lines, "\n"), width, height)
}

func (m tuiModel) renderListPane(width, height int) string {
	bodyWidth, bodyHeight := m.paneContentSize(width, height)
	m.listPane.Width = max(10, bodyWidth)
	m.listPane.Height = max(1, bodyHeight-1)
	m.refreshListContent()
	title := "Findings"
	if m.focusedPane == tuiPaneFindings {
		title += "  [FOCUS]"
	}
	return m.renderBoundedPane(title, m.listPane.View(), width, height)
}

func (m tuiModel) renderDetailPane(width, height int) string {
	bodyWidth, bodyHeight := m.paneContentSize(width, height)
	m.detailPane.Width = max(10, bodyWidth)
	m.detailPane.Height = max(4, bodyHeight-1)
	title := "Evidence / Details"
	if m.focusedPane == tuiPaneDetails {
		title += "  [FOCUS]"
	}
	return m.renderBoundedPane(title, m.detailPane.View(), width, height)
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

	titleLine := m.renderPaneTitle(title, innerWidth)
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

func (m tuiModel) renderPaneTitle(title string, width int) string {
	const focusSuffix = "  [FOCUS]"
	if !strings.HasSuffix(title, focusSuffix) {
		return m.styles.paneTitle.Render(padDisplayWidth(truncateDisplayWidth(title, width), width))
	}

	base := strings.TrimSuffix(title, focusSuffix)
	baseWidth := max(0, width-lipgloss.Width(focusSuffix))
	base = truncateDisplayWidth(base, baseWidth)
	line := m.styles.paneTitle.Render(base) + m.styles.paneFocus.Render(focusSuffix)
	return line + strings.Repeat(" ", max(0, width-lipgloss.Width(base)-lipgloss.Width(focusSuffix)))
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
	line := fmt.Sprintf("%s %-12s %-18s", meta, truncateDisplayWidth(strings.ToUpper(row.Triage), 12), truncateDisplayWidth(row.Category, 18))
	rowWidth := max(8, width)
	if row.Bookmarked {
		marker := lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E")).Render("*")
		line = truncateDisplayWidth(line, max(1, rowWidth-lipgloss.Width(marker)-1)) + " " + marker
	}
	line = padDisplayWidth(truncateDisplayWidth(line, rowWidth), rowWidth)
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
		for index, line := range evidence {
			if index > 0 && strings.TrimSpace(line) == "Context:" && strings.TrimSpace(evidence[index-1]) != "" {
				lines = append(lines, "")
			}
			lines = append(lines, line)
		}
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
		row := newTUIFindingRow(m.findings[idx])
		pathKey := bookmarkPathKey(m.findings[idx].Host, m.findings[idx].Share, m.findings[idx].FilePath)
		fileKey := m.bookmarkKeysByPath[pathKey]
		row.Bookmarked = fileKey != "" && m.bookmarkedFileKeys[fileKey]
		rows = append(rows, renderTUIFindingRow(row, m.listPane.Width, idx == m.selected))
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
		frame:            lipgloss.NewStyle().Padding(0, 1),
		header:           lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#D9ECFF")),
		headerStatusDone: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5BE49B")),
		headerMuted:      lipgloss.NewStyle().Foreground(lipgloss.Color("#88AECB")),
		pane:             lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#3B82F6")).Padding(0, 1),
		paneBorder:       lipgloss.NewStyle().Foreground(lipgloss.Color("#3B82F6")),
		paneTitle:        lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7CC4FF")),
		paneFocus:        lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD166")),
		selectedRow:      lipgloss.NewStyle().Foreground(lipgloss.Color("#F8FBFF")).Background(lipgloss.Color("#1D4ED8")).Bold(true),
		row:              lipgloss.NewStyle().Foreground(lipgloss.Color("#D7EAFE")),
		rowMuted:         lipgloss.NewStyle().Foreground(lipgloss.Color("#7A9BB7")),
		detailKey:        lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8CCBFF")),
		detailValue:      lipgloss.NewStyle().Foreground(lipgloss.Color("#EDF6FF")),
		detailAccent:     lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD166")),
		footer:           lipgloss.NewStyle().Foreground(lipgloss.Color("#8FAECC")),
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
	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		wrapped = append(wrapped, wrapDisplayLine(line, width)...)
	}
	return strings.Join(wrapped, "\n")
}

func wrapDisplayLine(value string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	if value == "" {
		return []string{""}
	}
	result := make([]string, 0, 1)
	var line strings.Builder
	for _, r := range []rune(value) {
		candidate := line.String() + string(r)
		if line.Len() > 0 && lipgloss.Width(candidate) > width {
			result = append(result, line.String())
			line.Reset()
		}
		line.WriteRune(r)
	}
	if line.Len() > 0 {
		result = append(result, line.String())
	}
	return result
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

func fitScreenBlock(value string, width, height int) string {
	if width <= 0 {
		return ""
	}
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		if lipgloss.Width(line) <= width {
			continue
		}
		if strings.Contains(line, "\x1b[") {
			lines[index] = charmansi.Truncate(line, width, "")
		} else {
			lines[index] = truncateDisplayWidth(line, width)
		}
	}
	if height > 0 {
		if len(lines) > height {
			lines = lines[:height]
		}
		for len(lines) < height {
			lines = append(lines, "")
		}
	}
	for i, line := range lines {
		lines[i] = padDisplayWidth(line, width)
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

package output

import (
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"snablr/internal/scanner"
	"snablr/internal/store"
)

// hostileEvidence contains sequences a terminal would execute: clear screen,
// cursor home, DEC line-drawing charset, OSC title, C1 CSI, backspace,
// carriage return, bell and a bidirectional override.
const hostileEvidence = "ok \x1b[2J\x1b[H CLEAR | \x1b(0lqqk DEC | \x1b]0;TITLE\x07 OSC | \u009b31m C1 | x\x08y BS | \u202eRTL | \r CR | © → end"

// styleSequence matches the only escape sequences the TUI itself emits:
// lipgloss SGR styling.
var styleSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func assertTerminalSafeView(t *testing.T, name, view string, width int) {
	t.Helper()
	stripped := styleSequence.ReplaceAllString(view, "")
	for _, r := range stripped {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
			t.Fatalf("%s: terminal control %U reached the screen", name, r)
		}
	}
	if !strings.Contains(stripped, "␛[2J") {
		t.Fatalf("%s: hostile evidence was not shown in visible form", name)
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > width {
			t.Fatalf("%s: line exceeds terminal width %d: %q", name, width, line)
		}
	}
}

// Evidence, paths and names from scanned shares must be displayed without
// executing terminal control sequences; they previously corrupted the TUI.
func TestLiveTUIRendersHostileEvidenceSafely(t *testing.T) {
	writer := &TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"}
	model := newTUIModel(writer)
	model.windowLoaded = true
	model.width = 110
	model.height = 30
	model.layout()
	finding := sampleFinding()
	finding.MatchedText = hostileEvidence
	finding.Context = hostileEvidence
	finding.Snippet = hostileEvidence
	finding.Match = hostileEvidence
	finding.FilePath = "dir/" + hostileEvidence + ".txt"
	finding.Share = "Share\x1b[2J"
	model.findings = []scanner.Finding{finding}
	model.selected = 0
	model.ensureSelectionVisible()
	model.refreshDetailContent(true)
	assertTerminalSafeView(t, "live view", model.View(), model.width)

	if original := model.findings[0].MatchedText; original != hostileEvidence {
		t.Fatal("rendering modified the stored finding evidence")
	}
}

func TestLiveTUISearchResultsRenderSafely(t *testing.T) {
	result := store.SearchResult{Type: store.SearchResultFinding, Title: hostileEvidence, Context: hostileEvidence, Source: "src\x1b[2J", Detail: hostileEvidence}
	assertNoControls := func(name, text string) {
		for _, r := range text {
			if (r < 0x20 && r != '\n') || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
				t.Fatalf("%s: terminal control %U survived: %q", name, r, text)
			}
		}
	}
	assertNoControls("search row", formatSearchResult(result))
	model := newTUIModel(&TUIWriter{summary: newSummaryCollector(), validationMode: newValidationModeCollector(), status: "running"})
	model.searchDetail = &result
	assertNoControls("search detail", model.searchDetailContent())
	if result.Title != hostileEvidence {
		t.Fatal("rendering modified the search result")
	}
}

func TestConsoleWriterPrintsHostileEvidenceSafely(t *testing.T) {
	var out strings.Builder
	writer := NewConsoleWriter(&out, nil)
	finding := sampleFinding()
	finding.Actionable = true
	finding.TriageClass = "actionable"
	finding.MatchedText = hostileEvidence
	finding.Context = hostileEvidence
	finding.FilePath = "dir/" + hostileEvidence
	if err := writer.writeFindingLocked(finding); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.String() {
		if (r < 0x20 && r != '\n') || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
			t.Fatalf("console output contains terminal control %U", r)
		}
	}
	if !strings.Contains(out.String(), "␛[2J") {
		t.Fatal("console output did not show hostile evidence in visible form")
	}
}

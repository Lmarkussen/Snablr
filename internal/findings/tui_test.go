package findings

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	"snablr/internal/scanner"
)

func TestFindingsModelNavigationAndLayout(t *testing.T) {
	m := &model{
		ctx:   context.Background(),
		scans: []Scan{{ID: "scan-synthetic", Status: "completed", FindingCount: 2}},
		items: []Finding{
			{Finding: scanner.Finding{RuleID: "one", RuleName: "First", Severity: "high", Host: "HOST", Share: "Share", FilePath: strings.Repeat("nested/", 8) + "evidence.txt", MatchedText: "synthetic evidence"}},
			{Finding: scanner.Finding{RuleID: "two", RuleName: "Second", Severity: "medium", MatchedText: "more evidence"}},
		},
		left: viewportForTest(), right: viewportForTest(),
	}
	m.resizeTo(100, 24)
	if got := m.View(); got == "" || !strings.Contains(got, "First") {
		t.Fatalf("unexpected initial view: %q", got)
	}
	if width := maxLineWidth(m.View()); width > 100 {
		t.Fatalf("view exceeds terminal width: %d", width)
	}
	m.move(1)
	if m.selectedItem != 1 || !strings.Contains(m.left.View(), "Second") {
		t.Fatal("finding selection did not update list")
	}
	m.focus = 1
	m.page(1)
	if !strings.Contains(m.right.View(), "more evidence") {
		t.Fatal("detail pane did not remain usable after focus change")
	}
}

func TestFindingsModelScanSelector(t *testing.T) {
	m := &model{selectingScan: true, selectedScan: 0, scans: []Scan{{ID: "newest"}, {ID: "older"}}, left: viewportForTest(), right: viewportForTest()}
	m.resizeTo(80, 20)
	m.move(1)
	if m.selectedScan != 1 || !strings.Contains(m.left.View(), "older") {
		t.Fatal("scan selector did not move selection")
	}
}

func (m *model) resizeTo(width, height int) {
	m.width, m.height = width, height
	m.resize()
}

func viewportForTest() viewport.Model { return viewport.New(1, 1) }

func maxLineWidth(value string) int {
	maxWidth := 0
	for _, line := range strings.Split(value, "\n") {
		if len([]rune(line)) > maxWidth {
			maxWidth = len([]rune(line))
		}
	}
	return maxWidth
}

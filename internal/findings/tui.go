package findings

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	provider      *Provider
	ctx           context.Context
	scans         []Scan
	selectedScan  int
	items         []Finding
	selectedItem  int
	focus         int
	selectingScan bool
	width, height int
	left, right   viewport.Model
	status        string
	loaded        bool
}

func Run(ctx context.Context, provider *Provider, scans []Scan, output io.Writer) error {
	if len(scans) == 0 {
		return fmt.Errorf("findings database contains no scan records")
	}
	m := &model{provider: provider, ctx: ctx, scans: scans, selectingScan: len(scans) > 1, left: viewport.New(1, 1), right: viewport.New(1, 1)}
	if len(scans) == 1 {
		if err := m.loadFindings(); err != nil {
			return err
		}
	}
	program := tea.NewProgram(m, tea.WithOutput(output), tea.WithAltScreen())
	_, err := program.Run()
	return err
}

func (m *model) loadFindings() error {
	items, err := m.provider.Findings(m.ctx, m.scans[m.selectedScan].ID, 0, PageSize)
	if err != nil {
		return err
	}
	m.items = items
	m.selectedItem = 0
	m.loaded = true
	if len(items) == PageSize && m.scans[m.selectedScan].FindingCount > PageSize {
		m.status = fmt.Sprintf("Showing first %d of %d findings", PageSize, m.scans[m.selectedScan].FindingCount)
	} else {
		m.status = fmt.Sprintf("Loaded %d findings", len(items))
	}
	return nil
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.focus = 1 - m.focus
		case "esc":
			if m.selectingScan {
				return m, tea.Quit
			}
		case "up", "k":
			m.move(-1)
		case "down", "j":
			m.move(1)
		case "pgup":
			m.page(-1)
		case "pgdown", "space":
			m.page(1)
		case "enter":
			if m.selectingScan {
				if err := m.loadFindings(); err != nil {
					m.status = err.Error()
				} else {
					m.selectingScan = false
					m.updateList()
					m.updateDetails()
				}
			}
		}
	}
	return m, nil
}

func (m *model) move(delta int) {
	if m.selectingScan {
		m.selectedScan = clamp(m.selectedScan+delta, 0, len(m.scans)-1)
		m.updateList()
		return
	}
	if m.focus == 0 && len(m.items) > 0 {
		m.selectedItem = clamp(m.selectedItem+delta, 0, len(m.items)-1)
		m.updateList()
		m.updateDetails()
	} else if m.focus == 1 {
		m.right.LineDown(delta)
	}
}

func (m *model) page(direction int) {
	if m.selectingScan || m.focus == 0 {
		m.move(direction * 8)
		return
	}
	if direction < 0 {
		m.right.PageUp()
	} else {
		m.right.PageDown()
	}
}

func (m *model) resize() {
	if m.width < 1 || m.height < 1 {
		return
	}
	headerHeight := 3
	footerHeight := 2
	bodyHeight := max(4, m.height-headerHeight-footerHeight)
	leftWidth := max(32, m.width*38/100)
	rightWidth := max(32, m.width-leftWidth-4)
	m.left.Width, m.left.Height = leftWidth-2, bodyHeight-2
	m.right.Width, m.right.Height = rightWidth-2, bodyHeight-2
	m.updateList()
	m.updateDetails()
}

func (m *model) updateList() {
	var lines []string
	if m.selectingScan {
		for i, scan := range m.scans {
			marker := "  "
			if i == m.selectedScan {
				marker = "▸ "
			}
			line := fmt.Sprintf("%s%s  %s  %s  %d findings", marker, scan.ID, scan.Status, scan.Started.Format("2006-01-02 15:04"), scan.FindingCount)
			if scan.Targets != "" {
				line += "  [" + scan.Targets + "]"
			}
			if i == m.selectedScan {
				line = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render(line)
			}
			lines = append(lines, line)
		}
		m.left.SetContent(strings.Join(lines, "\n"))
		return
	}
	for i, item := range m.items {
		marker, style := "  ", lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
		if i == m.selectedItem {
			marker, style = "▸ ", lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
		}
		severity := strings.ToUpper(item.Finding.Severity)
		lines = append(lines, style.Render(marker+severity+"  "+firstNonEmpty(item.Finding.RuleName, item.Finding.RuleID)))
	}
	m.left.SetContent(strings.Join(lines, "\n"))
}

func (m *model) updateDetails() {
	if m.selectingScan || len(m.items) == 0 {
		m.right.SetContent("Select a scan and press Enter to browse its findings.")
		return
	}
	f := m.items[m.selectedItem].Finding
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", firstNonEmpty(f.RuleName, f.RuleID))
	fmt.Fprintf(&b, "Severity: %s    Confidence: %s\n", f.Severity, firstNonEmpty(f.Confidence, "unknown"))
	fmt.Fprintf(&b, "Classification: %s\n", firstNonEmpty(f.TriageClass, "unspecified"))
	fmt.Fprintf(&b, "Actionable: %t\n", f.Actionable)
	fmt.Fprintf(&b, "Host: %s\nShare: %s\nPath: %s\n", f.Host, f.Share, f.FilePath)
	if f.ArchivePath != "" || f.ArchiveMemberPath != "" {
		fmt.Fprintf(&b, "Archive: %s!%s\n", f.ArchivePath, f.ArchiveMemberPath)
	}
	if len(f.MatchedRuleIDs) > 0 {
		fmt.Fprintf(&b, "Rule IDs: %s\n", strings.Join(f.MatchedRuleIDs, ", "))
	}
	if f.LineNumber > 0 {
		fmt.Fprintf(&b, "Line: %d\n", f.LineNumber)
	}
	b.WriteString("\nEvidence\n--------\n")
	b.WriteString(firstNonEmpty(f.MatchedText, f.Match, "No matched text persisted."))
	if f.Context != "" {
		b.WriteString("\n\nContext\n-------\n")
		b.WriteString(f.Context)
	}
	if f.Snippet != "" {
		b.WriteString("\n\nSnippet\n-------\n")
		b.WriteString(f.Snippet)
	}
	if f.MatchReason != "" {
		b.WriteString("\n\nWhy it matched\n---------------\n")
		b.WriteString(f.MatchReason)
	}
	m.right.SetContent(b.String())
}

func (m *model) View() string {
	if m.width < 1 || m.height < 1 {
		return "Loading Findings Engine..."
	}
	scan := m.scans[m.selectedScan]
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("SNABLR FINDINGS ENGINE") + "  " + scan.ID + "  " + scan.Status
	if scan.Targets != "" {
		header += "  " + scan.Targets
	}
	leftTitle, rightTitle := "Findings", "Evidence / Details"
	if m.focus == 0 {
		leftTitle += "  [FOCUS]"
	} else {
		rightTitle += "  [FOCUS]"
	}
	left := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39")).Padding(0, 1).Width(m.left.Width + 2).Height(m.left.Height + 2).Render(leftTitle + "\n" + m.left.View())
	right := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39")).Padding(0, 1).Width(m.right.Width + 2).Height(m.right.Height + 2).Render(rightTitle + "\n" + m.right.View())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Tab focus  ↑/↓ or j/k navigate  PgUp/PgDn scroll  Enter select scan  q quit  " + m.status)
	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "-"
}
func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

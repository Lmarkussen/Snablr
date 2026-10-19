package findings

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func TestCategoryFirstNavigationAndEvidence(t *testing.T) {
	categories := buildCategories([]Credential{{Candidate: credentialanalysis.Candidate{
		CredentialType: "password", Identity: "svc-build", Domain: "SYNTH", Value: "SyntheticPassword!", Verification: credentialanalysis.Confirmed, Path: "configs/app.ini", Host: "HOST", Share: "Share",
	}}}, nil, nil)
	m := &model{ctx: context.Background(), scans: []Scan{{ID: "scan", Status: "completed"}}, categories: categories, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 24)
	if !strings.Contains(m.View(), "Credentials") || !strings.Contains(m.View(), "svc-build") {
		t.Fatalf("category overview did not show meaningful discovery preview: %q", m.View())
	}
	m.open()
	if m.screen != screenSubcategories || len(m.subs) == 0 {
		t.Fatal("category did not open subcategories")
	}
	m.open()
	if m.screen != screenDiscoveries || len(m.discoveries) != 1 {
		t.Fatal("subcategory did not open actual discoveries")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if m.screen != screenEvidence || !strings.Contains(m.preview.View(), "SyntheticPassword!") {
		t.Fatalf("E did not open full persisted evidence: screen=%d content=%q", m.screen, m.preview.View())
	}
	m.back()
	if m.screen != screenDiscoveries || m.selectedDisc != 0 {
		t.Fatal("back navigation did not preserve discovery selection")
	}
}

func TestCategoryCountsDoNotPromoteSupportingFindings(t *testing.T) {
	items := buildCategories(nil, []Finding{{Finding: scanner.Finding{RuleID: "extension", Category: "configuration", TriageClass: "supporting", Actionable: false}}}, nil)
	if len(items) != 1 || items[0].Name != "Other / Supporting" {
		t.Fatal("supporting-only finding should remain accessible only in the supporting category")
	}
}

func TestModelWidthAndResize(t *testing.T) {
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{{Name: "Credentials", Discoveries: []discovery{{Title: "identity", Subcategory: "Username + Password"}}}}, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(72, 18)
	if maxLineWidth(m.View()) > 72 {
		t.Fatalf("category-first view exceeds terminal width")
	}
}

func TestCategoryOverviewFitsReportedTerminal(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {100, 30}, {120, 40}, {160, 50}, {200, 60}, {120, 90}, {70, 24}} {
		m := &model{
			scans: []Scan{{ID: "scan", Status: "completed"}},
			categories: []category{
				{Name: "Credentials", Discoveries: []discovery{{Title: "svc-build", Subcategory: "Username + Password"}}},
				{Name: "Private Keys", Discoveries: []discovery{{Title: "id_rsa", Subcategory: "RSA Keys"}}},
				{Name: "Hashes", Discoveries: []discovery{{Title: "synthetic-admin", Subcategory: "NT Hashes"}}},
				{Name: "Cloud & Application Secrets", Discoveries: []discovery{{Title: "api", Subcategory: "Tokens / API Secrets"}}},
				{Name: "SCCM / MECM", Discoveries: []discovery{{Title: "join", Subcategory: "Task Sequence Credentials"}}},
				{Name: "Windows Artifacts", Discoveries: []discovery{{Title: "wincred", Subcategory: "Credential Store Material"}}},
				{Name: "Correlations", Discoveries: []discovery{{Title: "relationship", Subcategory: "Cross-file Relationships"}}},
				{Name: "Other / Supporting", Discoveries: []discovery{{Title: "supporting", Subcategory: "Supporting Findings"}}},
			},
			list: viewport.New(1, 1), preview: viewport.New(1, 1),
		}
		m.resizeTo(size[0], size[1])
		view := m.View()
		lines := strings.Split(view, "\n")
		if len(lines) > size[1] {
			t.Fatalf("%dx%d rendered %d rows", size[0], size[1], len(lines))
		}
		if !strings.Contains(view, "Categories") || !strings.Contains(view, "Credentials") || !strings.Contains(view, "Q quit") {
			t.Fatalf("%dx%d lost category menu or footer: %q", size[0], size[1], view)
		}
		if maxLineWidth(view) > size[0] {
			t.Fatalf("%dx%d rendered a line wider than terminal", size[0], size[1])
		}
	}
}

func (m *model) resizeTo(width, height int) { m.width, m.height = width, height; m.resize() }
func maxLineWidth(value string) int {
	maxWidth := 0
	for _, line := range strings.Split(value, "\n") {
		if len([]rune(line)) > maxWidth {
			maxWidth = len([]rune(line))
		}
	}
	return maxWidth
}

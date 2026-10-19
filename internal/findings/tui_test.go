package findings

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
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
	if m.screen != screenDiscoveries || !strings.Contains(m.preview.View(), "SyntheticPassword!") {
		t.Fatalf("discovery did not show full persisted evidence: screen=%d content=%q", m.screen, m.preview.View())
	}
	m.back()
	if m.screen != screenSubcategories || m.selectedSub != 0 {
		t.Fatal("back navigation did not preserve subcategory selection")
	}
}

func TestDiscoverySelectionUpdatesFullDetailsWithoutEvidenceScreen(t *testing.T) {
	item := category{Name: "Credentials", Discoveries: []discovery{
		{Title: "first", Subcategory: "Passwords", MaterialType: "password", Value: "first-secret", Verification: "confirmed"},
		{Title: "second", Subcategory: "Passwords", MaterialType: "password", Value: "second-secret", Verification: "confirmed"},
	}}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{item}, screen: screenDiscoveries, discoveries: item.Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 24)
	if !strings.Contains(m.preview.View(), "first-secret") || strings.Contains(m.View(), "E evidence") {
		t.Fatalf("initial discovery details or footer incorrect: %q", m.View())
	}
	m.move(1)
	if !strings.Contains(m.preview.View(), "second-secret") || strings.Contains(m.preview.View(), "first-secret") {
		t.Fatalf("selection did not replace full details: %q", m.preview.View())
	}
}

func TestFinderFocusIndicatorAndPaneNavigation(t *testing.T) {
	item := category{Name: "Credentials", Discoveries: []discovery{{Title: "identity", Subcategory: "Passwords", Value: "secret"}}}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{item}, screen: screenCategories, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	if !strings.Contains(m.View(), "Categories [FOCUS]") || strings.Contains(m.View(), "Preview [FOCUS]") {
		t.Fatalf("upper focus indicator incorrect: %q", m.View())
	}
	oldFocus := m.focus
	m.toggleFocus()
	if m.focus == oldFocus || !strings.Contains(m.View(), "Preview [FOCUS]") || strings.Contains(m.View(), "Categories [FOCUS]") {
		t.Fatalf("tab did not switch only the active focus: %q", m.View())
	}
	if m.preview.Height <= 18 {
		t.Fatalf("details panel did not receive additional room: %d", m.preview.Height)
	}
	if strings.Contains(subcategoryPreview(item, []string{"Passwords"}, 0), "press Enter") {
		t.Fatal("subcategory preview retained redundant navigation instructions")
	}
}

func TestCategoryCountsDoNotPromoteSupportingFindings(t *testing.T) {
	items := buildCategories(nil, []Finding{{Finding: scanner.Finding{RuleID: "extension", Category: "configuration", TriageClass: "supporting", Actionable: false}}}, nil)
	if len(items) != 1 || items[0].Name != "Original Findings" {
		t.Fatal("supporting-only finding should remain accessible only in the supporting category")
	}
}

func TestFinderClassificationUsesPersistedMaterialType(t *testing.T) {
	tests := []struct {
		name, typ, value, wantCategory, wantSubcategory string
	}{
		{"password", "password", "Synthetic!", "Credentials", "Password Only"},
		{"hash", "nt_hash", "00112233445566778899aabbccddeeff", "Hashes & Captures", "NT Hashes"},
		{"netntlm", "netntlmv2", "user::domain:challenge:proof:blob", "Hashes & Captures", "NetNTLMv2"},
		{"key", "private_key", "-----BEGIN RSA PRIVATE KEY-----", "Keys & Certificates", "RSA Keys"},
		{"review", "password", "${UNRESOLVED}", "Review", "Potential Credentials"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verification := credentialanalysis.Confirmed
			if test.name == "review" {
				verification = credentialanalysis.Review
			}
			category, subcategory := classifyCandidate(credentialanalysis.Candidate{
				CredentialType: test.typ, Value: test.value, Verification: verification,
			})
			if category != test.wantCategory || subcategory != test.wantSubcategory {
				t.Fatalf("classification = %q / %q, want %q / %q", category, subcategory, test.wantCategory, test.wantSubcategory)
			}
		})
	}
}

func TestPrivateKeyClassificationDoesNotUseFilename(t *testing.T) {
	category, subcategory := classifyCandidate(credentialanalysis.Candidate{
		CredentialType: "private_key", Value: "-----BEGIN PRIVATE KEY-----", Path: "keys/id_rsa", Verification: credentialanalysis.Confirmed,
	})
	if category != "Keys & Certificates" || subcategory != "Other Private Keys" {
		t.Fatalf("filename inferred a key subtype: %q / %q", category, subcategory)
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
				{Name: "Keys & Certificates", Discoveries: []discovery{{Title: "id_rsa", Subcategory: "RSA Keys"}}},
				{Name: "Hashes & Captures", Discoveries: []discovery{{Title: "synthetic-admin", Subcategory: "NT Hashes"}}},
				{Name: "Cloud & Application Secrets", Discoveries: []discovery{{Title: "api", Subcategory: "Tokens / API Secrets"}}},
				{Name: "Windows & Deployment Artifacts", Discoveries: []discovery{{Title: "join", Subcategory: "Task Sequence Credentials"}}},
				{Name: "Windows Artifacts", Discoveries: []discovery{{Title: "wincred", Subcategory: "Credential Store Material"}}},
				{Name: "Correlations", Discoveries: []discovery{{Title: "relationship", Subcategory: "Cross-file Relationships"}}},
				{Name: "Original Findings", Discoveries: []discovery{{Title: "supporting", Subcategory: "Supporting Findings"}}},
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

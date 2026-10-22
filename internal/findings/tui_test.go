package findings

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
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

func TestDatabaseLocationFindingsUseDedicatedCategory(t *testing.T) {
	categories := buildCategories(nil, []Finding{{Finding: scanner.Finding{
		RuleID: "dbinspect.artifact.sqlite_structural", RuleName: "Structurally Validated SQLite Database Artifact",
		Category: "database-artifacts", SignalType: "validated", Confidence: "high", FilePath: "exports/opaque-copy",
	}}}, nil)
	if len(categories) != 1 || categories[0].Name != "Database Locations & Connections" {
		t.Fatalf("expected dedicated database category, got %#v", categories)
	}
	if len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "Database Files & Backups" {
		t.Fatalf("unexpected database location projection: %#v", categories[0])
	}
}

func TestWindowsArtifactFindingsUseDedicatedCategoryAndSubcategory(t *testing.T) {
	categories := buildCategories(nil, []Finding{{Finding: scanner.Finding{
		RuleID: "windowsinspect.registry_export.structured", RuleName: "Windows Registry Editor Export", Category: "windows-deployment", SignalType: "validated", Confidence: "high", FilePath: "export.reg", MatchedText: "Windows Registry Editor Version 5.00",
	}}}, nil)
	if len(categories) != 1 || categories[0].Name != "Windows & Deployment Artifacts" {
		t.Fatalf("expected Windows artifact category, got %#v", categories)
	}
	if len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "Registry Exports" {
		t.Fatalf("unexpected Windows artifact projection: %#v", categories[0].Discoveries)
	}
}

func TestSCCMArtifactFindingsUseInfrastructureSubcategories(t *testing.T) {
	categories := buildCategories(nil, []Finding{{Finding: scanner.Finding{
		RuleID: "sccminspect.infrastructure.distribution_point", RuleName: "SCCM Distribution Point", Category: "windows-deployment", SignalType: "validated", Confidence: "high", FilePath: "sccm.json",
	}}}, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 || categories[0].Discoveries[0].Subcategory != "SCCM Infrastructure & Distribution Points" {
		t.Fatalf("unexpected SCCM projection: %#v", categories)
	}
}

func TestStructuredDatabaseEndpointUsesServerSubcategory(t *testing.T) {
	categories := buildCategories(nil, []Finding{{Finding: scanner.Finding{
		RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Validated Database Configuration Endpoint",
		Category: "database-infrastructure", SignalType: "validated", Confidence: "high", FilePath: "config/app.json",
	}}}, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 {
		t.Fatalf("expected one structured database discovery, got %#v", categories)
	}
	if categories[0].Discoveries[0].Subcategory != "Database Servers & Instances" {
		t.Fatalf("unexpected structured endpoint subcategory: %#v", categories[0].Discoveries[0])
	}
}

func TestDatabaseLocationCategoryPreservesDistinctConnections(t *testing.T) {
	categories := buildCategories(nil, []Finding{
		{Finding: scanner.Finding{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Validated Database Configuration Endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", FilePath: "config/app.json", MatchedText: "production"}},
		{Finding: scanner.Finding{RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Validated Database Configuration Endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", FilePath: "config/app.json", MatchedText: "reporting"}},
	}, nil)
	if len(categories) != 1 || len(categories[0].Discoveries) != 2 {
		t.Fatalf("distinct configured endpoints were collapsed: %#v", categories)
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

func TestEvidenceFirstAndSecretHighlighting(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(previous)

	secret := category{Name: "Credentials", Discoveries: []discovery{{Title: "secret", MaterialFamily: "Credentials", MaterialType: "password", Value: "SyntheticSecret!", Verification: "confirmed"}}}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{secret}, screen: screenDiscoveries, discoveries: secret.Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 24)
	view := m.preview.View()
	if strings.Index(view, "RECOVERED EVIDENCE") > strings.Index(view, "Material family:") {
		t.Fatalf("secret metadata preceded evidence: %q", view)
	}
	if !strings.Contains(view, "38;2;251;146;60m") {
		t.Fatalf("secret evidence was not highlighted orange: %q", view)
	}

	observed := category{Name: "Database Locations & Connections", Discoveries: []discovery{{Title: "SQLite", MaterialFamily: "Database Locations & Connections", MaterialType: "database artifact", Value: "SQLite format 3\\x00", Verification: "review"}}}
	m = &model{scans: []Scan{{ID: "scan"}}, categories: []category{observed}, screen: screenDiscoveries, discoveries: observed.Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 24)
	view = m.preview.View()
	if !strings.Contains(view, "OBSERVED EVIDENCE") || strings.Contains(view, "38;2;251;146;60m") {
		t.Fatalf("non-secret evidence styling was incorrect: %q", view)
	}
}

func TestDisplayScanStatusUsesOperatorFriendlyLabels(t *testing.T) {
	for input, want := range map[string]string{
		"completed":            "completed",
		"completed_with_skips": "completed with skips",
		"timed_out":            "timed out",
		"failed":               "failed",
	} {
		if got := displayScanStatus(input); got != want {
			t.Fatalf("displayScanStatus(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestFinderFocusIndicatorAndPaneNavigation(t *testing.T) {
	item := category{Name: "Credentials", Discoveries: []discovery{{Title: "identity", Subcategory: "Passwords", Value: "secret"}}}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{item}, screen: screenCategories, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	view := m.View()
	if !strings.Contains(view, "Categories") || strings.Count(view, "[FOCUS]") != 1 || strings.Contains(view, "Preview") && strings.Contains(view, "Preview [FOCUS]") {
		t.Fatalf("upper focus indicator incorrect: %q", m.View())
	}
	oldFocus := m.focus
	m.toggleFocus()
	view = m.View()
	if m.focus == oldFocus || !strings.Contains(view, "Preview") || strings.Count(view, "[FOCUS]") != 1 {
		t.Fatalf("tab did not switch only the active focus: %q", m.View())
	}
	if m.preview.Height <= 18 {
		t.Fatalf("details panel did not receive additional room: %d", m.preview.Height)
	}
	if strings.Contains(subcategoryPreview(item, []string{"Passwords"}, 0), "press Enter") {
		t.Fatal("subcategory preview retained redundant navigation instructions")
	}
}

func TestPanelHeaderEmitsOrangeFocusColor(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(previous)

	header := panelHeader("Categories", true, 80, lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true))
	if !strings.Contains(header, "[FOCUS]") {
		t.Fatalf("focus label missing from header: %q", header)
	}
	if !strings.Contains(header, "38;2;251;146;60m") {
		t.Fatalf("orange true-color sequence missing from final header: %q", header)
	}
	if strings.Contains(header, "\x1b[38;2;42;") {
		t.Fatalf("focus header used the green heading color: %q", header)
	}
}

func TestCategoryRowsKeepCountColumnFixed(t *testing.T) {
	items := []category{
		{Name: "Credentials", Discoveries: make([]discovery, 1)},
		{Name: "Connection & Database Secrets", Discoveries: make([]discovery, 12)},
		{Name: "A deliberately long category label that must be clipped", Discoveries: make([]discovery, 1234)},
	}
	var expected int
	for selected := range items {
		lines := strings.Split(categoryList(items, selected, 80), "\n")
		if len(lines) != len(items) {
			t.Fatalf("selected=%d rendered %d rows", selected, len(lines))
		}
		for i, line := range lines {
			count := len(fmt.Sprintf("%d", len(items[i].Discoveries)))
			position := lipgloss.Width(line) - count
			if i == 0 && selected == 0 {
				expected = position
			}
			if lipgloss.Width(line) != 80 {
				t.Fatalf("selected=%d row=%d width=%d, want 80", selected, i, lipgloss.Width(line))
			}
			if i == 0 && selected != 0 && lipgloss.Width(line)-count != expected {
				t.Fatalf("selected=%d count alignment changed", selected)
			}
			if strings.Contains(line, "CRITICAL") || strings.Contains(line, "HIGH") || strings.Contains(line, "INFO") {
				t.Fatalf("category row retained severity text: %q", line)
			}
		}
	}
}

func TestFinderHasNoGlobalBreadcrumbAtAnyLevel(t *testing.T) {
	item := category{Name: "Credentials", Discoveries: []discovery{{Title: "identity", Subcategory: "Passwords", Value: "secret"}}}
	m := &model{scans: []Scan{{ID: "scan", Status: "completed"}}, categories: []category{item}, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 30)
	assertNoBreadcrumb := func(level string) {
		if strings.Contains(m.View(), "Credentials >") {
			t.Fatalf("%s view retained global breadcrumb: %q", level, m.View())
		}
	}
	assertNoBreadcrumb("categories")
	m.open()
	assertNoBreadcrumb("subcategories")
	m.open()
	assertNoBreadcrumb("discoveries")
	m.back()
	assertNoBreadcrumb("back navigation")

	m.selectingScan = true
	assertNoBreadcrumb("scan selection")
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
		{"password", "password", "Synthetic!", "Review", "Password Only"},
		{"hash", "nt_hash", "00112233445566778899aabbccddeeff", "Hashes & Captures", "NT Hashes"},
		{"netntlm", "netntlmv2", "user::domain:challenge:proof:blob", "Hashes & Captures", "NetNTLMv2"},
		{"asrep", "kerberos_asrep", "asrep-record", "Hashes & Captures", "Kerberos AS-REP"},
		{"tgs", "kerberos_tgs", "tgs-record", "Hashes & Captures", "Kerberos TGS"},
		{"dcc", "dcc", "dcc-record", "Hashes & Captures", "DCC1"},
		{"dcc2", "dcc2", "dcc2-record", "Hashes & Captures", "DCC2"},
		{"key", "private_key", "-----BEGIN RSA PRIVATE KEY-----", "Keys & Certificates", "RSA Keys"},
		{"review", "password", "${UNRESOLVED}", "Review", "Password Only"},
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

func TestFinderPairingPolicyRejectsOpaqueAndKeepsGenericReviewSecret(t *testing.T) {
	candidate := credentialanalysis.Candidate{Verification: credentialanalysis.Review, CredentialType: "secret", Identity: "cfg-user", Value: "cfg-secret", Path: "config/cfg.json", Evidence: []credentialanalysis.Evidence{{Path: "config/cfg.json"}}}
	decision := interpretCredential(candidate)
	if decision.Confirmed || decision.Status != "Uncertain pairing" {
		t.Fatalf("generic review secret decision = %#v", decision)
	}
	if category, _ := classifyCandidate(candidate); category != "Review" {
		t.Fatalf("generic review secret classified as %q", category)
	}
	opaque := credentialanalysis.Candidate{Verification: credentialanalysis.Confirmed, CredentialType: "password", Identity: "opaque-user", Value: "BASE64-CIPHERTEXT-NOT-PLAINTEXT", ValidationBasis: "windows_unattend_structured_password", Path: "negative/encrypted.xml", Evidence: []credentialanalysis.Evidence{{Path: "negative/encrypted.xml"}}}
	decision = interpretCredential(opaque)
	if decision.Confirmed || !decision.Opaque || decision.Status != "Encrypted / opaque material" {
		t.Fatalf("opaque decision = %#v", decision)
	}
}

func TestFinderPairingPolicyKeepsPasswordOnlyMaterialInReview(t *testing.T) {
	candidate := credentialanalysis.Candidate{
		Verification:   credentialanalysis.Review,
		CredentialType: "password",
		Value:          "PasswordOnly!",
		Path:           "scripts/example.ps1",
		Evidence:       []credentialanalysis.Evidence{{Path: "scripts/example.ps1"}},
	}
	decision := interpretCredential(candidate)
	if decision.Confirmed || decision.Status != "Password only / identity not established" {
		t.Fatalf("password-only decision = %#v", decision)
	}
	if category, _ := classifyCandidate(candidate); category != "Review" {
		t.Fatalf("password-only material classified as %q", category)
	}
	categories := buildCategories([]Credential{{Candidate: candidate}}, nil, nil)
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	text := m.evidenceText()
	for _, want := range []string{"PASSWORD ONLY — IDENTITY NOT ESTABLISHED", "Pairing: not confirmed", "Username: not safely established", "Password: PasswordOnly!"} {
		if !strings.Contains(text, want) {
			t.Fatalf("password-only evidence missing %q: %q", want, text)
		}
	}
}

func TestFinderDerivedPairEvidenceShowsPairingBasis(t *testing.T) {
	candidate := credentialanalysis.Candidate{
		Verification:    credentialanalysis.Review,
		CredentialType:  "secret",
		Identity:        "cfg-user",
		Value:           "CfgSecret!",
		Path:            "config/settings.ini",
		Host:            "synthetic-host",
		Share:           "share_iso",
		Evidence:        []credentialanalysis.Evidence{{Path: "config/settings.ini"}},
		ValidationBasis: "structured configuration scope",
	}
	categories := buildCategories([]Credential{{Candidate: candidate}}, nil, nil)
	if len(categories) != 1 || categories[0].Name != "Credentials" {
		t.Fatalf("derived pair categories = %#v", categories)
	}
	discovery := categories[0].Discoveries[0]
	if discovery.PairingStatus != "Confirmed pair (Finder-derived)" || discovery.OriginalVerification != "review" {
		t.Fatalf("derived discovery = %#v", discovery)
	}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	for _, want := range []string{"USERNAME + PASSWORD COMBINATION", "Username: cfg-user", "Password: CfgSecret!", "Pairing: Confirmed pair (Finder-derived)", "Original persisted verification: review"} {
		if !strings.Contains(m.evidenceText(), want) {
			t.Fatalf("derived pair evidence missing %q: %q", want, m.evidenceText())
		}
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
		if !strings.Contains(view, "Categories") || !strings.Contains(view, "Credentials") || !strings.Contains(view, "Ctrl-C quit") {
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

func TestCredentialOriginClassificationAndPresentation(t *testing.T) {
	cases := []struct {
		name, domain, source, basis, wantOrigin, wantSubcategory string
	}{
		{name: "domain", domain: "SYNTHETIC", wantOrigin: "AD / Domain Credential", wantSubcategory: "AD / Domain"},
		{name: "sccm", source: "SCCM task sequence", wantOrigin: "SCCM / MECM Credential", wantSubcategory: "SCCM / MECM"},
		{name: "unknown", wantOrigin: "Unknown Origin Credential", wantSubcategory: "Unknown Origin"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := credentialanalysis.Candidate{CredentialType: "password", Identity: "svc", Domain: test.domain, Source: test.source, ValidationBasis: test.basis, Value: "synthetic-value", Verification: credentialanalysis.Confirmed}
			category, subcategory := classifyCandidate(candidate)
			if category != "Credentials" || subcategory != test.wantSubcategory {
				t.Fatalf("classification = %q / %q, want Credentials / %q", category, subcategory, test.wantSubcategory)
			}
			if got := originType(candidate); got != test.wantOrigin {
				t.Fatalf("origin = %q, want %q", got, test.wantOrigin)
			}
		})
	}

	categories := buildCategories([]Credential{{Candidate: credentialanalysis.Candidate{
		CredentialType: "password", Identity: "join-xml", Domain: "SYNTHETIC", Value: "Synthetic-SCCM-XML-482!", Source: "SCCM task sequence", Host: "HOST", Share: "Share", Path: "task.xml", Verification: credentialanalysis.Confirmed,
	}}}, nil, nil)
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	details := m.preview.View()
	for _, want := range []string{"RECOVERED EVIDENCE", "Synthetic-SCCM-XML-482!", "USERNAME + PASSWORD COMBINATION", "Username: SYNTHETIC\\join-xml", "Password: Synthetic-SCCM-XML-482!", "Origin type: SCCM / MECM Credential"} {
		if !strings.Contains(details, want) {
			t.Fatalf("details missing %q: %q", want, details)
		}
	}
	m.preview.GotoBottom()
	if !strings.Contains(m.preview.View(), "Source: task.xml") {
		t.Fatalf("details did not remain accessible after scrolling: %q", m.preview.View())
	}
}

func TestConnectionStringDetailsAreStructuredWithoutChangingValue(t *testing.T) {
	candidate := credentialanalysis.Candidate{CredentialType: "connection_string", Value: "Server=db01;Initial Catalog=Snablr;User ID=app-user;Password=Odd;Provider=SQLOLEDB", Verification: credentialanalysis.Confirmed}
	if got := originType(candidate); got != "MSSQL / Database Credential" {
		t.Fatalf("origin = %q, want MSSQL / Database Credential", got)
	}
	details := connectionDetails(candidate)
	if len(details) != 5 || details[0].Label != "Server / Host" || details[1].Value != "Snablr" || details[3].Value != "Odd" {
		t.Fatalf("connection details = %#v", details)
	}
	categories := buildCategories([]Credential{{Candidate: candidate}}, nil, nil)
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	for _, want := range []string{"CONNECTION STRING FIELDS", "Server / Host: db01", "Database / Catalog: Snablr", "Username: app-user", "Password: Odd", "Provider / Driver: SQLOLEDB", "Server=db01;Initial Catalog=Snablr"} {
		if !strings.Contains(m.evidenceText(), want) {
			t.Fatalf("connection details missing %q: %q", want, m.preview.View())
		}
	}
}

func TestKeyPresentationUsesValidatedMaterialType(t *testing.T) {
	candidate := credentialanalysis.Candidate{CredentialType: "private_key", Value: "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----", Verification: credentialanalysis.Confirmed, Path: "keys/id_ed25519"}
	categories := buildCategories([]Credential{{Candidate: candidate}}, nil, nil)
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, screen: screenDiscoveries, discoveries: categories[0].Discoveries, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	for _, want := range []string{"KEY / CERTIFICATE MATERIAL", "Key or certificate type: OpenSSH private key", "BEGIN OPENSSH PRIVATE KEY"} {
		if !strings.Contains(m.preview.View(), want) {
			t.Fatalf("key details missing %q: %q", want, m.preview.View())
		}
	}
}

func TestAllPersistedMaterialReusesDiscoveryReferencesAndStatuses(t *testing.T) {
	credentials := []Credential{
		{CredentialKey: "confirmed", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "DOMAIN\\alice", Value: "SyntheticOne!", Verification: credentialanalysis.Confirmed, Path: "one.ini", Host: "HOST", Share: "Share"}},
		{CredentialKey: "derived", Candidate: credentialanalysis.Candidate{CredentialType: "secret", Identity: "DOMAIN\\bob", Value: "SyntheticTwo!", Verification: credentialanalysis.Review, ValidationBasis: "structured configuration scope", Path: "two.ini", Host: "HOST", Share: "Share"}},
		{CredentialKey: "opaque", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "DOMAIN\\opaque", Value: "BASE64-CIPHERTEXT-NOT-PLAINTEXT", Verification: credentialanalysis.Confirmed, Path: "encrypted.xml", Host: "HOST", Share: "Share"}},
		{CredentialKey: "password-only", Candidate: credentialanalysis.Candidate{CredentialType: "password", Value: "OnlyValue!", Verification: credentialanalysis.Review, Path: "only.ini", Host: "HOST", Share: "Share"}},
	}
	categories, audit := buildCategoriesWithAccounting("scan", credentials, nil, nil)
	if audit.UnaccountedRows != 0 {
		t.Fatalf("normal projection lost rows: %#v", audit)
	}
	all := buildAllPersistedMaterial(categories)
	if len(all.Discoveries) != 4 {
		t.Fatalf("all material count = %d, want 4", len(all.Discoveries))
	}
	statuses := map[string]bool{}
	for _, item := range all.Discoveries {
		statuses[item.Subcategory] = true
		if len(item.PersistedRefs) != 1 {
			t.Fatalf("discovery lost persisted reference: %#v", item)
		}
	}
	for _, want := range []string{"Confirmed Username + Password", "Finder-Derived Pair", "Encrypted / Opaque", "Password Only"} {
		if !statuses[want] {
			t.Fatalf("missing all-material status %q: %#v", want, statuses)
		}
	}
}

func TestAllPersistedMaterialFilterMatchesMaterialAndProvenance(t *testing.T) {
	items := []discovery{
		{Title: "DOMAIN\\alice", Subcategory: "Confirmed Username + Password", MaterialType: "password", Identity: "DOMAIN\\alice", Value: "SyntheticOne!", Host: "HOST-A", Share: "Share-A", Path: "configs/one.ini", Sources: []string{"\\\\HOST-A\\Share-A\\configs/one.ini"}},
		{Title: "DOMAIN\\bob", Subcategory: "Password Only", MaterialType: "password", Value: "SyntheticTwo!", Host: "HOST-B", Share: "Share-B", Path: "configs/two.ini", Sources: []string{"\\\\HOST-B\\Share-B\\configs/two.ini"}},
	}
	for query, want := range map[string]string{"alice": "DOMAIN\\alice", "host-b": "DOMAIN\\bob", "password only": "DOMAIN\\bob", "one.ini": "DOMAIN\\alice"} {
		filtered := filterDiscoveries(items, query)
		if len(filtered) != 1 || filtered[0].Title != want {
			t.Fatalf("filter %q = %#v, want %q", query, filtered, want)
		}
	}
	if got := filterDiscoveries(items, "not-present"); len(got) != 0 {
		t.Fatalf("empty filter returned %d discoveries", len(got))
	}
}

func TestAllPersistedMaterialNavigationAndRowTrace(t *testing.T) {
	credentials := []Credential{{CredentialKey: "same-a", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "user", Value: "same", Verification: credentialanalysis.Confirmed, Path: "a.ini"}}, {CredentialKey: "same-b", Candidate: credentialanalysis.Candidate{CredentialType: "password", Identity: "user", Value: "same", Verification: credentialanalysis.Confirmed, Path: "b.ini"}}}
	categories, audit := buildCategoriesWithAccounting("scan", credentials, nil, nil)
	m := &model{scans: []Scan{{ID: "scan"}}, categories: categories, allMaterial: buildAllPersistedMaterial(categories), list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	if !strings.Contains(m.View(), "All Persisted Material") {
		t.Fatalf("all-material entry missing from overview: %q", m.View())
	}
	m.open()
	if m.screen != screenSubcategories || len(m.subs) != 1 || m.subs[0] != "Confirmed Username + Password" {
		t.Fatalf("unexpected all-material subcategories: %#v", m.subs)
	}
	m.open()
	if m.screen != screenDiscoveries || len(m.discoveries) != 1 || len(m.discoveries[0].PersistedRefs) != 2 {
		t.Fatalf("grouped row references not preserved: %#v", m.discoveries)
	}
	if !strings.Contains(m.preview.View(), "Persisted rows: 2") {
		t.Fatalf("details did not expose persisted row count: %q", m.preview.View())
	}
	m.preview.SetYOffset(1000)
	if !strings.Contains(m.preview.View(), "Persisted row: same-a") || !strings.Contains(m.preview.View(), "Persisted row: same-b") {
		t.Fatalf("details did not expose persisted row trace while scrolled: %q", m.preview.View())
	}
	if audit.TotalPersistedRows != 2 || audit.PresentedRows != 1 || audit.GroupedRows != 1 || audit.UnaccountedRows != 0 {
		t.Fatalf("accounting changed by all-material navigation: %#v", audit)
	}
}

func makeDiscoveryList(count int) []discovery {
	items := make([]discovery, count)
	for index := range items {
		items[index] = discovery{Title: fmt.Sprintf("discovery-%02d", index+1), Subcategory: "Confirmed Username + Password", MaterialType: "password", Identity: fmt.Sprintf("user-%02d", index+1), Value: fmt.Sprintf("value-%02d", index+1), Verification: "confirmed", Path: fmt.Sprintf("%02d.ini", index+1)}
	}
	return items
}

func TestDiscoverySelectionKeepsListViewportAndDetailsSynchronized(t *testing.T) {
	items := makeDiscoveryList(50)
	m := &model{scans: []Scan{{ID: "scan"}}, screen: screenDiscoveries, discoveries: items, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	m.list.Height = 12
	m.refresh()
	for index := 0; index < 29; index++ {
		m.move(1)
	}
	if m.selectedDisc != 29 {
		t.Fatalf("selected index = %d, want 29", m.selectedDisc)
	}
	if m.list.YOffset <= 0 {
		t.Fatalf("list viewport did not advance: offset=%d", m.list.YOffset)
	}
	if !strings.Contains(m.list.View(), "discovery-30") {
		t.Fatalf("selected discovery is not visible: offset=%d view=%q", m.list.YOffset, m.list.View())
	}
	if !strings.Contains(m.preview.View(), "value-30") {
		t.Fatalf("details are stale for selected discovery: %q", m.preview.View())
	}
	for index := 29; index > 0; index-- {
		m.move(-1)
		if !strings.Contains(m.list.View(), fmt.Sprintf("discovery-%02d", index)) {
			t.Fatalf("selection %d is not visible while moving upward: offset=%d view=%q", index, m.list.YOffset, m.list.View())
		}
	}
	if m.list.YOffset != 0 || !strings.Contains(m.list.View(), "discovery-01") {
		t.Fatalf("list did not return to top: offset=%d view=%q", m.list.YOffset, m.list.View())
	}
}

func TestDiscoveryViewportUsesAvailableHeightAfterOpening(t *testing.T) {
	items := category{Name: "Credentials", Discoveries: makeDiscoveryList(50)}
	m := &model{scans: []Scan{{ID: "scan"}}, categories: []category{items}, allMaterial: category{}, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(120, 40)
	m.open()
	m.open()
	if m.screen != screenDiscoveries {
		t.Fatalf("screen = %d, want discoveries", m.screen)
	}
	if m.list.Height < 18 {
		t.Fatalf("discoveries pane remained too short: height=%d", m.list.Height)
	}
	if m.preview.Height < 8 {
		t.Fatalf("details pane became unusably short: height=%d", m.preview.Height)
	}
	if !strings.Contains(m.View(), "discovery-01") || !strings.Contains(m.View(), "Ctrl-C quit") {
		t.Fatalf("rendered discoveries view lost list or footer: %q", m.View())
	}
}

func TestFilteredDiscoverySelectionAndEmptyDetails(t *testing.T) {
	items := makeDiscoveryList(50)
	m := &model{scans: []Scan{{ID: "scan"}}, screen: screenDiscoveries, discoveries: items, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(100, 30)
	m.preview.Height = 100
	m.allMaterial = category{Name: "All Persisted Material", Discoveries: items}
	m.selected = 0
	m.subs = []string{"Confirmed Username + Password"}
	m.selectedSub = 0
	m.filter = "user-30"
	m.refresh()
	if len(m.discoveries) != 1 || m.selectedDisc != 0 || !strings.Contains(m.preview.View(), "value-30") {
		t.Fatalf("filtered discovery state incorrect: selected=%d discoveries=%d details=%q", m.selectedDisc, len(m.discoveries), m.preview.View())
	}
	m.filter = "does-not-exist"
	m.refresh()
	if len(m.discoveries) != 0 || strings.Contains(m.preview.View(), "value-30") || !strings.Contains(m.preview.View(), "No discovery selected") {
		t.Fatalf("empty filter retained stale details: discoveries=%d details=%q", len(m.discoveries), m.preview.View())
	}
}

func TestResizeKeepsDeepSelectionVisible(t *testing.T) {
	items := makeDiscoveryList(50)
	m := &model{scans: []Scan{{ID: "scan"}}, screen: screenDiscoveries, discoveries: items, selectedDisc: 35, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(160, 50)
	m.refresh()
	if !strings.Contains(m.list.View(), "discovery-36") {
		t.Fatalf("deep selection not visible after large resize: %q", m.list.View())
	}
	m.resizeTo(80, 24)
	if !strings.Contains(m.list.View(), "discovery-36") {
		t.Fatalf("deep selection not visible after compact resize: %q", m.list.View())
	}
}

func TestFinderKeepsReviewPasswordIdentityUncertain(t *testing.T) {
	candidate := credentialanalysis.Candidate{
		Verification:   credentialanalysis.Review,
		CredentialType: "password",
		Identity:       "primary-user",
		Value:          "SecondaryPass!",
		Path:           "database/review.properties",
		Evidence:       []credentialanalysis.Evidence{{Path: "database/review.properties"}},
	}
	decision := interpretCredential(candidate)
	if decision.Confirmed || decision.Status != "Uncertain pairing" {
		t.Fatalf("review password was promoted: %#v", decision)
	}
}

func TestDetailsViewportScrollsUpFromBottomWithoutFocusReset(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{
		{name: "120x40", width: 120, height: 40},
		{name: "80x24", width: 80, height: 24},
	} {
		t.Run(size.name, func(t *testing.T) {
			item := category{Name: "Credentials", Discoveries: []discovery{{Title: "long-detail"}}}
			m := &model{
				scans:       []Scan{{ID: "scan"}},
				categories:  []category{item},
				screen:      screenDiscoveries,
				discoveries: item.Discoveries,
				focus:       1,
				list:        viewport.New(1, 1),
				preview:     viewport.New(1, 1),
			}
			m.width, m.height = size.width, size.height
			m.resize()
			lines := make([]string, 0, m.preview.Height*4+8)
			for index := 0; index < cap(lines); index++ {
				lines = append(lines, fmt.Sprintf("detail line %03d", index))
			}
			m.preview.SetContent(strings.Join(lines, "\n"))
			m.preview.GotoBottom()
			bottom := m.preview.YOffset
			if bottom <= 0 {
				t.Fatalf("test content did not exceed viewport: height=%d lines=%d", m.preview.Height, len(lines))
			}

			m.Update(tea.KeyMsg{Type: tea.KeyUp})
			if m.preview.YOffset != bottom-1 {
				t.Fatalf("up from bottom moved to offset %d, want %d", m.preview.YOffset, bottom-1)
			}
			for index := 0; index < bottom+2; index++ {
				m.Update(tea.KeyMsg{Type: tea.KeyUp})
			}
			if m.preview.YOffset != 0 {
				t.Fatalf("repeated up did not reach top: offset=%d", m.preview.YOffset)
			}
			for index := 0; index < bottom+2; index++ {
				m.Update(tea.KeyMsg{Type: tea.KeyDown})
			}
			if m.preview.YOffset != bottom {
				t.Fatalf("repeated down did not return to bottom: offset=%d want=%d", m.preview.YOffset, bottom)
			}
		})
	}
}

func TestDetailsWrapPreservesLongEvidenceAndUnicode(t *testing.T) {
	long := `{"type":"same_identity_value","sources":[{"path":"\\\\host\\share\\very-long-directory\\credential-æøå-file.txt"}],"value":"` + strings.Repeat("x", 180) + `"}`
	wrapped := wrapDetails(long, 24)
	if strings.ReplaceAll(wrapped, "\n", "") != long {
		t.Fatalf("wrapped evidence lost content: %q", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		if lipgloss.Width(line) > 24 {
			t.Fatalf("wrapped line exceeds viewport: width=%d line=%q", lipgloss.Width(line), line)
		}
	}
}

func TestCorrelationDetailsExplainSourcesAndPreserveRawRecord(t *testing.T) {
	payload := `{"type":"same_identity_value","identity":"shared-observation","credential_type":"password","sources":[{"host":"host","share":"share","path":"one.txt"},{"host":"host","share":"share","path":"two.txt"},{"host":"host","share":"share","path":"two.txt"}],"observation_count":2,"confidence":"high","confidence_rationale":"same identity and material in distinct source files"}`
	categories := buildCategories(nil, nil, []Correlation{{Key: "credential:test", Payload: payload}})
	if len(categories) != 1 || len(categories[0].Discoveries) != 1 {
		t.Fatalf("unexpected correlation projection: %#v", categories)
	}
	d := categories[0].Discoveries[0]
	if d.Title != "Same identity/value relationship — 2 source observations" {
		t.Fatalf("unexpected correlation title: %q", d.Title)
	}
	m := &model{scans: []Scan{{ID: "scan"}}, screen: screenDiscoveries, discoveries: []discovery{d}, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	m.resizeTo(80, 24)
	text := m.evidenceText()
	for _, want := range []string{"OBSERVED EVIDENCE", "same identity and material", `\\host\share\one.txt`, `\\host\share\two.txt`, "RAW RECORD", `"same_identity_value"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("correlation details missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "Persisted rows: 0") || strings.Contains(text, "Source observations: 0") {
		t.Fatalf("correlation details exposed misleading material counts: %s", text)
	}
}

func TestMalformedCorrelationKeepsRawPayload(t *testing.T) {
	payload := `{"type":"unknown","sources":[broken]}`
	categories := buildCategories(nil, nil, []Correlation{{Key: "credential:malformed", Payload: payload}})
	d := categories[0].Discoveries[0]
	text := correlationEvidenceText(d)
	if !strings.Contains(text, "Raw record is not valid JSON") || !strings.Contains(text, payload) {
		t.Fatalf("malformed correlation payload was not preserved: %s", text)
	}
}

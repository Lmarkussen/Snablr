package findings

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

type screen int

const (
	screenCategories screen = iota
	screenSubcategories
	screenDiscoveries
)

type discovery struct {
	Title, Subcategory, MaterialType, Identity, Domain string
	MaterialFamily, SourceContext                      string
	OriginType                                         string
	Value, Host, Share, Path, Confidence, Verification string
	Reason                                             string
	PairingStatus, PairingBasis, OriginalVerification  string
	ConnectionDetails                                  []connectionDetail
	Sources                                            []string
	PersistedRefs                                      []string
	Finding                                            *scanner.Finding
}

type connectionDetail struct {
	Label string
	Value string
}

type category struct {
	Name, Description string
	Discoveries       []discovery
}

type model struct {
	provider      *Provider
	ctx           context.Context
	output        io.Writer
	scans         []Scan
	selectedScan  int
	selectingScan bool
	screen        screen
	focus         int
	selected      int
	selectedSub   int
	selectedDisc  int
	categories    []category
	subs          []string
	discoveries   []discovery
	findings      []Finding
	width, height int
	list, preview viewport.Model
	previewHeight int
	status        string
}

// Run starts the offline viewer. It only queries the supplied read-only provider.
func Run(ctx context.Context, provider *Provider, scans []Scan, output io.Writer) error {
	if len(scans) == 0 {
		return fmt.Errorf("findings database contains no scan records")
	}
	m := &model{provider: provider, ctx: ctx, output: output, scans: scans, selectingScan: len(scans) > 1, list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	if len(scans) == 1 {
		if err := m.loadScan(); err != nil {
			return err
		}
	}
	program := tea.NewProgram(m, tea.WithOutput(output), tea.WithAltScreen())
	_, err := program.Run()
	return err
}

func (m *model) loadScan() error {
	findings, err := readAllFindings(m.ctx, m.provider, m.scans[m.selectedScan].ID)
	if err != nil {
		return err
	}
	credentials, err := readAllCredentials(m.ctx, m.provider, m.scans[m.selectedScan].ID)
	if err != nil {
		return err
	}
	correlations, err := readAllCorrelations(m.ctx, m.provider, m.scans[m.selectedScan].ID)
	if err != nil {
		return err
	}
	m.findings = findings
	categories, audit := buildCategoriesWithAccounting(m.scans[m.selectedScan].ID, credentials, findings, correlations)
	if audit.UnaccountedRows != 0 {
		return fmt.Errorf("findings credential projection accounting failed: %d unaccounted rows (%s)", audit.UnaccountedRows, strings.Join(audit.UnaccountedRefs, ", "))
	}
	m.categories = categories
	m.selected, m.selectedSub, m.selectedDisc = 0, 0, 0
	m.screen = screenCategories
	m.status = fmt.Sprintf("%d categories · %d findings · %d logical credentials · %d correlations", len(m.categories), len(findings), len(credentials), len(correlations))
	m.refresh()
	return nil
}

func readAllFindings(ctx context.Context, provider *Provider, scanID string) ([]Finding, error) {
	var result []Finding
	for offset := 0; ; offset += PageSize {
		page, err := provider.Findings(ctx, scanID, offset, PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < PageSize {
			return result, nil
		}
	}
}

func readAllCredentials(ctx context.Context, provider *Provider, scanID string) ([]Credential, error) {
	var result []Credential
	for offset := 0; ; offset += PageSize {
		page, err := provider.Credentials(ctx, scanID, offset, PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < PageSize {
			return result, nil
		}
	}
}

func readAllCorrelations(ctx context.Context, provider *Provider, scanID string) ([]Correlation, error) {
	var result []Correlation
	for offset := 0; ; offset += PageSize {
		page, err := provider.Correlations(ctx, scanID, offset, PageSize)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if len(page) < PageSize {
			return result, nil
		}
	}
}

func buildCategories(credentials []Credential, findings []Finding, correlations []Correlation) []category {
	categories, _ := buildCategoriesWithAccounting("", credentials, findings, correlations)
	return categories
}

func buildCategoriesWithAccounting(scanID string, credentials []Credential, findings []Finding, correlations []Correlation) ([]category, ProjectionAudit) {
	ordered := []struct {
		name, description string
	}{
		{"Credentials", "Confirmed and review-level plaintext credential material"},
		{"Keys & Certificates", "Validated private-key and certificate material"},
		{"Hashes & Captures", "Validated NT hash and NetNTLM capture material"},
		{"Application & Cloud Secrets", "Tokens, API keys, and application authentication material"},
		{"Connection & Database Secrets", "Connection strings, DSNs, and database credentials"},
		{"Windows & Deployment Artifacts", "Windows, SCCM, and deployment evidence"},
		{"Correlations", "Persisted cross-file relationships and supporting observations"},
		{"Review", "Candidates requiring operator review or stronger context"},
		{"Original Findings", "Original actionable and supporting scan observations"},
	}
	groups := make(map[string]*category, len(ordered))
	for _, item := range ordered {
		groups[item.name] = &category{Name: item.name, Description: item.description}
	}
	type discoveryRef struct {
		category string
		index    int
	}
	seen := make(map[string]discoveryRef)
	for _, item := range credentials {
		candidate := item.Candidate
		pairing := interpretCredential(candidate)
		name, sub := classifyCandidate(candidate)
		key := strings.Join([]string{candidate.CredentialType, candidate.Identity, candidate.Domain, candidate.Value}, "\x00")
		rowRef := credentialRowRef(item)
		if key == "\x00\x00\x00" || strings.TrimSpace(candidate.Value) == "" {
			key = rowRef
		}
		if ref, ok := seen[key]; ok && ref.category == name {
			group := groups[name]
			group.Discoveries[ref.index].PersistedRefs = appendUnique(group.Discoveries[ref.index].PersistedRefs, rowRef)
			group.Discoveries[ref.index].Sources = appendUnique(group.Discoveries[ref.index].Sources, sourceLabel(candidate))
			group.Discoveries[ref.index].SourceContext = appendContext(group.Discoveries[ref.index].SourceContext, sourceContext(candidate))
			group.Discoveries[ref.index].OriginType = mergeOrigin(group.Discoveries[ref.index].OriginType, originType(candidate))
			continue
		}
		d := discovery{
			Title:                discoveryTitle(candidate),
			Subcategory:          sub,
			MaterialType:         candidate.CredentialType,
			Identity:             candidate.Identity,
			Domain:               candidate.Domain,
			Value:                candidate.Value,
			Host:                 candidate.Host,
			Share:                candidate.Share,
			Path:                 candidate.Path,
			Confidence:           string(candidate.Verification),
			Verification:         firstNonEmpty(pairing.Status, string(candidate.Verification)),
			PairingStatus:        pairing.Status,
			PairingBasis:         pairing.Basis,
			OriginalVerification: pairing.OriginalVerification,
			MaterialFamily:       name,
			SourceContext:        sourceContext(candidate),
			OriginType:           originType(candidate),
			Reason:               strings.Join(candidate.ReviewReasons, "; "),
			ConnectionDetails:    connectionDetails(candidate),
			Sources:              []string{sourceLabel(candidate)},
			PersistedRefs:        []string{rowRef},
		}
		group := groups[name]
		seen[key] = discoveryRef{category: name, index: len(group.Discoveries)}
		group.Discoveries = append(group.Discoveries, d)
	}
	for _, item := range findings {
		f := item.Finding
		if !f.Actionable && !strings.EqualFold(f.TriageClass, "review") {
			if len(groups["Original Findings"].Discoveries) < 50 {
				groups["Original Findings"].Discoveries = append(groups["Original Findings"].Discoveries, discovery{
					Title: firstNonEmpty(f.RuleName, f.RuleID), Subcategory: "Supporting Findings", MaterialType: "supporting finding",
					Host: f.Host, Share: f.Share, Path: f.FilePath, Confidence: firstNonEmpty(f.Confidence, "unknown"), Verification: "supporting",
					Sources: []string{sourceLabelFinding(f)}, Finding: &f,
				})
			}
			continue
		}
		name := "Original Findings"
		group := groups[name]
		group.Discoveries = append(group.Discoveries, discovery{
			Title:          firstNonEmpty(f.RuleName, f.RuleID),
			Subcategory:    firstNonEmpty(f.TriageClass, "Original Findings"),
			MaterialFamily: name,
			MaterialType:   "scanner finding",
			Identity:       f.PotentialAccount,
			Host:           f.Host,
			Share:          f.Share,
			Path:           f.FilePath,
			Confidence:     firstNonEmpty(f.Confidence, "unknown"),
			Verification:   firstNonEmpty(f.TriageClass, "actionable"),
			Reason:         f.MatchReason,
			Sources:        []string{sourceLabelFinding(f)},
			Finding:        &f,
		})
	}
	for _, item := range correlations {
		groups["Correlations"].Discoveries = append(groups["Correlations"].Discoveries, discovery{
			Title: item.Key, Subcategory: "Cross-file Relationships", MaterialType: "correlation", Value: item.Payload,
			Verification: "persisted", Confidence: "contextual",
		})
	}
	result := make([]category, 0, len(ordered))
	for _, item := range ordered {
		if group := groups[item.name]; len(group.Discoveries) > 0 {
			result = append(result, *group)
		}
	}
	return result, auditCredentialProjection(scanID, credentials, result)
}

func classifyCandidate(candidate credentialanalysis.Candidate) (string, string) {
	pairing := interpretCredential(candidate)
	if pairing.Opaque || strings.TrimSpace(candidate.Value) == "" || (isUsernamePasswordType(candidate.CredentialType) && !pairing.Confirmed) {
		return "Review", reviewSubcategory(candidate)
	}
	typ := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	switch typ {
	case "nt_hash", "hash":
		return "Hashes & Captures", "NT Hashes"
	case "netntlmv1":
		return "Hashes & Captures", "NetNTLMv1"
	case "netntlmv2":
		return "Hashes & Captures", "NetNTLMv2"
	case "private_key":
		return "Keys & Certificates", privateKeySubcategory(candidate)
	case "certificate":
		return "Keys & Certificates", "Certificates"
	case "connection_string", "dsn":
		return "Connection & Database Secrets", "Connection Strings"
	case "token", "bearer_token", "access_token", "session_token", "api_key", "apikey", "api_secret", "access_key", "secret_key", "client_secret":
		return "Application & Cloud Secrets", "Tokens / API Secrets"
	case "password", "passwd", "pwd", "passord", "secret", "shared_secret":
		if candidate.Identity != "" {
			return "Credentials", credentialOriginSubcategory(originType(candidate))
		}
		return "Credentials", "Password Only"
	default:
		return "Credentials", "Other Credential Material"
	}
}

func credentialOriginSubcategory(origin string) string {
	switch origin {
	case "AD / Domain Credential":
		return "AD / Domain"
	case "SCCM / MECM Credential":
		return "SCCM / MECM"
	case "MSSQL / Database Credential", "Database Credential":
		return "Database / MSSQL"
	case "Web / Application Credential":
		return "Web / Application"
	case "Local Account Credential", "Local / Generic Credential":
		return "Local / Generic"
	default:
		return "Unknown Origin"
	}
}

func originType(candidate credentialanalysis.Candidate) string {
	typ := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	context := sourceContext(candidate)
	if context == "SCCM / MECM" {
		return "SCCM / MECM Credential"
	}
	if typ == "connection_string" || typ == "dsn" {
		if connectionLooksLikeMSSQL(candidate.Value) {
			return "MSSQL / Database Credential"
		}
		return "Connection String Credential"
	}
	if candidate.Domain != "" {
		return "AD / Domain Credential"
	}
	if typ == "token" || typ == "bearer_token" || typ == "access_token" || typ == "session_token" || typ == "api_key" || typ == "apikey" || typ == "api_secret" || typ == "access_key" || typ == "secret_key" || typ == "client_secret" {
		return "Web / Application Credential"
	}
	if strings.Contains(strings.ToLower(candidate.AccountType), "local") {
		return "Local Account Credential"
	}
	if typ == "password" || typ == "passwd" || typ == "pwd" || typ == "passord" || typ == "secret" || typ == "shared_secret" {
		return "Unknown Origin Credential"
	}
	return "Unknown Origin Credential"
}

func mergeOrigin(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" || existing == next {
		return existing
	}
	return "Unknown Origin Credential"
}

func connectionLooksLikeMSSQL(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "sql server") || strings.Contains(value, "mssql") || strings.Contains(value, "sqloledb") || strings.Contains(value, "sqlncli")
}

func connectionDetails(candidate credentialanalysis.Candidate) []connectionDetail {
	if typ := strings.ToLower(strings.TrimSpace(candidate.CredentialType)); typ != "connection_string" && typ != "dsn" {
		return nil
	}
	var details []connectionDetail
	for _, part := range strings.Split(candidate.Value, ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		label := connectionFieldLabel(key)
		if label == "" {
			continue
		}
		duplicate := false
		for _, existing := range details {
			if existing.Label == label {
				duplicate = true
				break
			}
		}
		if !duplicate {
			details = append(details, connectionDetail{Label: label, Value: strings.TrimSpace(value)})
		}
	}
	return details
}

func connectionFieldLabel(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "server", "data source", "address", "addr", "host":
		return "Server / Host"
	case "initial catalog", "database", "catalog":
		return "Database / Catalog"
	case "user id", "uid", "username", "user":
		return "Username"
	case "password", "pwd":
		return "Password"
	case "provider", "provider name", "driver":
		return "Provider / Driver"
	case "dsn":
		return "DSN"
	default:
		return ""
	}
}

func reviewSubcategory(candidate credentialanalysis.Candidate) string {
	if isOpaqueCredential(candidate) {
		return "Encrypted Credential Material"
	}
	if strings.TrimSpace(candidate.Value) == "" {
		return "Identity or Reference Only"
	}
	if isUsernamePasswordType(candidate.CredentialType) && strings.TrimSpace(candidate.Identity) == "" {
		return "Password Only"
	}
	if strings.EqualFold(candidate.CredentialType, "private_key") {
		return "Unparsed Key Material"
	}
	return "Potential Credentials"
}

func privateKeySubcategory(candidate credentialanalysis.Candidate) string {
	value := strings.ToLower(candidate.Value)
	if strings.Contains(value, "openssh") || strings.Contains(value, "ed25519") || strings.Contains(value, "begin ssh") {
		return "OpenSSH Keys"
	}
	if strings.Contains(value, "begin rsa") {
		return "RSA Keys"
	}
	return "Other Private Keys"
}

func sourceContext(candidate credentialanalysis.Candidate) string {
	value := strings.ToLower(strings.Join([]string{candidate.Source, candidate.Path, candidate.Container, candidate.ValidationBasis}, " "))
	switch {
	case strings.Contains(value, "sccm") || strings.Contains(value, "mecm") || strings.Contains(value, "tasksequence") || strings.Contains(value, "osd"):
		return "SCCM / MECM"
	case strings.Contains(value, "aws") || strings.Contains(value, "azure") || strings.Contains(value, "cloud"):
		return "Cloud / Application"
	case strings.Contains(value, "sam") || strings.Contains(value, "ntds") || strings.Contains(value, "wincred") || strings.Contains(value, "browser"):
		return "Windows"
	default:
		return ""
	}
}

func appendContext(existing, value string) string {
	if existing == "" {
		return value
	}
	if value == "" || existing == value {
		return existing
	}
	return existing + ", " + value
}

func discoveryTitle(candidate credentialanalysis.Candidate) string {
	if candidate.Identity != "" {
		if candidate.Domain != "" {
			return candidate.Domain + `\` + candidate.Identity
		}
		return candidate.Identity
	}
	if candidate.Path != "" {
		return "Material from " + candidate.Path
	}
	return firstNonEmpty(candidate.CredentialType, "Unidentified material")
}

func sourceLabel(candidate credentialanalysis.Candidate) string {
	if candidate.Host != "" || candidate.Share != "" {
		return fmt.Sprintf("\\\\%s\\%s\\%s", candidate.Host, candidate.Share, strings.TrimPrefix(candidate.Path, `/`))
	}
	return candidate.Path
}

func sourceLabelFinding(f scanner.Finding) string {
	return fmt.Sprintf("\\\\%s\\%s\\%s", f.Host, f.Share, strings.TrimPrefix(f.FilePath, `/`))
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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
			m.toggleFocus()
		case "up", "k":
			m.move(-1)
		case "down", "j":
			m.move(1)
		case "pgup":
			m.page(-1)
		case "pgdown", "space":
			m.page(1)
		case "enter", "right":
			if m.focus == 0 {
				m.open()
			}
		case "left", "esc":
			m.back()
		}
	}
	return m, nil
}

func (m *model) toggleFocus() {
	// Focus is local view state only; switching panes performs no database work.
	m.focus = 1 - m.focus
}

func (m *model) move(delta int) {
	if m.selectingScan {
		m.selectedScan = clamp(m.selectedScan+delta, 0, len(m.scans)-1)
		m.refresh()
		return
	}
	if m.focus == 1 {
		m.preview.LineDown(delta)
		return
	}
	switch m.screen {
	case screenCategories:
		m.selected = clamp(m.selected+delta, 0, len(m.categories)-1)
	case screenSubcategories:
		m.selectedSub = clamp(m.selectedSub+delta, 0, len(m.subs)-1)
	case screenDiscoveries:
		m.selectedDisc = clamp(m.selectedDisc+delta, 0, len(m.discoveries)-1)
	}
	m.refresh()
}

func (m *model) page(direction int) {
	if m.focus == 1 {
		if direction < 0 {
			m.preview.PageUp()
		} else {
			m.preview.PageDown()
		}
		return
	}
	m.move(direction * 8)
}

func (m *model) open() {
	if m.selectingScan {
		if err := m.loadScan(); err != nil {
			m.status = err.Error()
		} else {
			m.selectingScan = false
		}
		m.refresh()
		return
	}
	switch m.screen {
	case screenCategories:
		m.subs = categorySubcategories(m.categories[m.selected])
		m.selectedSub = 0
		m.screen = screenSubcategories
	case screenSubcategories:
		m.discoveries = subcategoryDiscoveries(m.categories[m.selected], m.subs[m.selectedSub])
		m.selectedDisc = 0
		m.screen = screenDiscoveries
	}
	m.focus = 0
	m.refresh()
}

func (m *model) back() {
	switch m.screen {
	case screenDiscoveries:
		m.screen = screenSubcategories
	case screenSubcategories:
		m.screen = screenCategories
	default:
		return
	}
	m.focus = 0
	m.refresh()
}

func categorySubcategories(item category) []string {
	seen := map[string]bool{}
	var result []string
	for _, d := range item.Discoveries {
		if !seen[d.Subcategory] {
			seen[d.Subcategory] = true
			result = append(result, d.Subcategory)
		}
	}
	sort.Strings(result)
	return result
}

func subcategoryDiscoveries(item category, sub string) []discovery {
	result := make([]discovery, 0)
	for _, d := range item.Discoveries {
		if d.Subcategory == sub {
			result = append(result, d)
		}
	}
	return result
}

func (m *model) refresh() {
	if m.selectingScan {
		m.list.SetContent(scanList(m.scans, m.selectedScan))
		m.preview.SetContent("No scan selected.")
		return
	}
	switch m.screen {
	case screenCategories:
		m.list.SetContent(categoryList(m.categories, m.selected, m.list.Width))
		m.preview.SetContent(categoryPreview(m.categories, m.selected))
	case screenSubcategories:
		m.list.SetContent(subcategoryList(m.subs, m.selectedSub))
		m.preview.SetContent(subcategoryPreview(m.categories[m.selected], m.subs, m.selectedSub))
	case screenDiscoveries:
		m.list.SetContent(discoveryList(m.discoveries, m.selectedDisc))
		m.preview.GotoTop()
		m.preview.SetContent(m.evidenceText())
	}
}

func (m *model) evidenceText() string {
	if len(m.discoveries) == 0 {
		return "No discovery selected."
	}
	d := m.discoveries[m.selectedDisc]
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\nMaterial family: %s\nMaterial type: %s\nVerification: %s\nConfidence: %s\n", evidenceSection("DISCOVERY"), d.Title, firstNonEmpty(d.MaterialFamily, "unknown"), firstNonEmpty(d.MaterialType, "unknown"), firstNonEmpty(d.Verification, "unknown"), firstNonEmpty(d.Confidence, "unknown"))
	if strings.EqualFold(d.MaterialFamily, "Credentials") && d.Value != "" {
		if d.Identity != "" {
			fmt.Fprintf(&b, "\n%s\n", evidenceSection("USERNAME + PASSWORD COMBINATION"))
			fmt.Fprintf(&b, "%s %s\n%s %s\n", evidenceLabel("Username:"), evidenceValue(qualifiedIdentity(d)), evidencePasswordLabel("Password:"), evidenceValue(d.Value))
		} else {
			fmt.Fprintf(&b, "\n%s\n", evidenceSection("PASSWORD MATERIAL"))
			b.WriteString("Username: not safely established\n")
			fmt.Fprintf(&b, "%s %s\n", evidencePasswordLabel("Password:"), evidenceValue(d.Value))
		}
		fmt.Fprintf(&b, "Credential kind: %s\nOrigin type: %s\n", firstNonEmpty(credentialKind(d.MaterialType), "credential material"), firstNonEmpty(d.OriginType, "Unknown Origin Credential"))
	} else if strings.EqualFold(d.MaterialFamily, "Keys & Certificates") {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("KEY / CERTIFICATE MATERIAL"))
		fmt.Fprintf(&b, "Key or certificate type: %s\n", firstNonEmpty(keyType(d), "validated material"))
		if d.Identity != "" {
			fmt.Fprintf(&b, "Associated identity: %s\n", qualifiedIdentity(d))
		}
		if d.Value != "" {
			b.WriteString("\nRecovered material\n")
			b.WriteString(d.Value)
			b.WriteByte('\n')
		}
	} else if d.Value != "" {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("RECOVERED MATERIAL"))
		b.WriteString(evidenceValue(d.Value))
		b.WriteByte('\n')
	}
	if d.OriginType != "" && !strings.EqualFold(d.MaterialFamily, "Credentials") {
		fmt.Fprintf(&b, "\nOrigin type: %s\n", d.OriginType)
	}
	if len(d.ConnectionDetails) > 0 {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("CONNECTION STRING FIELDS"))
		for _, detail := range d.ConnectionDetails {
			fmt.Fprintf(&b, "%s: %s\n", detail.Label, detail.Value)
		}
	}
	fmt.Fprintf(&b, "\n%s\n%s\n", evidenceSection("IDENTITY"), firstNonEmpty(qualifiedIdentity(d), "not persisted"))
	if d.SourceContext != "" {
		fmt.Fprintf(&b, "Source context: %s\n", d.SourceContext)
	}
	fmt.Fprintf(&b, "Host: %s\nShare: %s\nSource: %s\n", firstNonEmpty(d.Host, "not persisted"), firstNonEmpty(d.Share, "not persisted"), firstNonEmpty(d.Path, "not persisted"))
	if len(d.Sources) > 0 {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("SOURCE OBSERVATIONS"))
		b.WriteString(strings.Join(d.Sources, "\n"))
		b.WriteByte('\n')
	}
	if d.PairingStatus != "" {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("EVIDENCE QUALITY"))
		fmt.Fprintf(&b, "Pairing: %s\n", evidenceStatus(d.PairingStatus))
		fmt.Fprintf(&b, "Basis: %s\n", firstNonEmpty(d.PairingBasis, "not persisted"))
		if strings.Contains(d.Verification, "Finder-derived") && d.OriginalVerification != "" {
			fmt.Fprintf(&b, "Original persisted verification: %s\n", d.OriginalVerification)
		}
	}
	if d.Reason != "" {
		b.WriteString("\nClassification notes\n--------------------\n")
		b.WriteString(d.Reason)
		b.WriteByte('\n')
	}
	if d.Finding != nil {
		f := d.Finding
		fmt.Fprintf(&b, "\nOriginal finding\n----------------\nRule: %s\nSeverity: %s\nCategory: %s\n", firstNonEmpty(f.RuleName, f.RuleID), f.Severity, f.Category)
		if f.MatchedRuleIDs != nil {
			fmt.Fprintf(&b, "Rule IDs: %s\n", strings.Join(f.MatchedRuleIDs, ", "))
		}
		if f.MatchedText != "" {
			b.WriteString("\nEvidence\n--------\n")
			b.WriteString(f.MatchedText)
			b.WriteByte('\n')
		}
		if f.Context != "" {
			b.WriteString("\nContext\n-------\n")
			b.WriteString(f.Context)
			b.WriteByte('\n')
		}
		if f.Snippet != "" {
			b.WriteString("\nSnippet\n-------\n")
			b.WriteString(f.Snippet)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func evidenceSection(title string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#60A5FA")).Render(title)
}

func evidenceLabel(label string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#B5C4D0")).Render(label)
}

func evidencePasswordLabel(label string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FB923C")).Render(label)
}

func evidenceValue(value string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#EDF4F8")).Render(value)
}

func evidenceStatus(value string) string {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("#FBBF24"))
	if strings.Contains(strings.ToLower(value), "confirmed") {
		style = style.Foreground(lipgloss.Color("#5BE49B"))
	}
	return style.Bold(true).Render(value)
}

func qualifiedIdentity(d discovery) string {
	if d.Identity == "" {
		return ""
	}
	if d.Domain != "" && !strings.Contains(d.Identity, `\`) {
		return d.Domain + `\` + d.Identity
	}
	return d.Identity
}

func credentialKind(materialType string) string {
	return credentialanalysis.CredentialTypeDisplayName(materialType)
}

func keyType(d discovery) string {
	switch d.Subcategory {
	case "RSA Keys":
		return "RSA private key"
	case "OpenSSH Keys":
		return "OpenSSH private key"
	case "Certificates":
		return "certificate"
	default:
		return d.MaterialType
	}
}

func (m *model) resize() {
	if m.width < 1 || m.height < 1 {
		return
	}
	listRows := 1
	switch m.screen {
	case screenCategories:
		listRows = len(m.categories)
	case screenSubcategories:
		listRows = len(m.subs)
	case screenDiscoveries:
		listRows = min(len(m.discoveries), max(1, m.height/2))
	}
	if m.selectingScan {
		listRows = min(len(m.scans), max(1, m.height/2))
	}
	listRows = max(1, listRows)
	m.list.Width, m.list.Height = max(20, m.width-6), listRows
	// Header, footer, and each panel's title/borders consume fixed
	// rows. Only the remaining rows belong to the preview viewport.
	panelRows := listRows + 3
	remaining := m.height - 2 - panelRows - 3
	// Keep the overview compact on tall terminals; unused space below the
	// footer is preferable to stretching a small preview into a blank panel.
	// Give details more room on ordinary terminals while keeping a bounded
	// viewport on very tall terminals.
	m.previewHeight = min(max(0, remaining), 24)
	m.preview.Width, m.preview.Height = max(20, m.width-6), max(1, m.previewHeight)
	m.refresh()
}

func (m *model) View() string {
	if m.width < 1 || m.height < 1 {
		return "Loading Findings Engine..."
	}
	scan := m.scans[m.selectedScan]
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("SNABLR // FINDINGS") + "  " + scan.ID + "  " + scan.Status
	if scan.Targets != "" {
		header += "  " + scan.Targets
	}
	if m.selectingScan {
		return m.frame(header, "", "Scans", m.list.View(), "", m.preview.View())
	}
	if m.screen == screenCategories {
		return m.frame(header, "", "Categories", m.list.View(), "Preview", m.preview.View())
	}
	return m.frame(header, "", "Discoveries", m.list.View(), "Details", m.preview.View())
}

func (m *model) frame(header, crumb, leftTitle, leftContent, rightTitle, rightContent string) string {
	style := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39")).Padding(0, 1)
	section := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	if leftTitle == "" {
		panel := style.Render(panelHeader(rightTitle, false, m.preview.Width, section) + "\n" + rightContent)
		footer := "PgUp/PgDn scroll  ←/Esc back  Q quit"
		return joinFinderSections(header, crumb, panel, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(footer+"  "+m.status))
	}
	left := style.Render(panelHeader(leftTitle, m.focus == 0, m.list.Width, section) + "\n" + leftContent)
	preview := style.Render(panelHeader(rightTitle, m.focus == 1, m.preview.Width, section) + "\n" + rightContent)
	footer := "↑/↓ j/k move  Enter/→ open  ←/Esc back  PgUp/PgDn scroll  Q quit"
	if m.screen == screenCategories || m.selectingScan {
		footer = "↑/↓ j/k move  Enter/→ select  Q quit"
	}
	return joinFinderSections(header, crumb, left, preview, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(footer+"  "+m.status))
}

func joinFinderSections(sections ...string) string {
	filtered := make([]string, 0, len(sections))
	for _, section := range sections {
		if section != "" {
			filtered = append(filtered, section)
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, filtered...)
}

func panelHeader(title string, focused bool, width int, section lipgloss.Style) string {
	if !focused {
		return section.Render(title)
	}
	focusText := "[FOCUS]"
	focusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FB923C")).Bold(true)
	if width < lipgloss.Width(focusText)+2 {
		return focusStyle.Render(focusText)
	}
	gap := width - lipgloss.Width(title) - lipgloss.Width(focusText)
	if gap < 1 {
		gap = 1
	}
	return section.Render(title) + strings.Repeat(" ", gap) + focusStyle.Render(focusText)
}

func scanList(scans []Scan, selected int) string {
	var lines []string
	for i, scan := range scans {
		marker := "  "
		if i == selected {
			marker = "▸ "
		}
		lines = append(lines, marker+scan.ID+"  "+scan.Status+"  "+scan.Targets+fmt.Sprintf("  %d findings", scan.FindingCount))
	}
	return strings.Join(lines, "\n")
}
func categoryList(items []category, selected, width int) string {
	var lines []string
	arrow := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	selectedName := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	const arrowWidth = 2
	const countWidth = 8
	nameWidth := max(12, width-arrowWidth-countWidth-2)
	for i, item := range items {
		name := truncateDisplay(item.Name, nameWidth)
		marker := "  "
		if i == selected {
			marker = arrow.Render("▸") + " "
			name = selectedName.Render(name)
		}
		namePadding := max(0, nameWidth-lipgloss.Width(name))
		lines = append(lines, marker+name+strings.Repeat(" ", namePadding)+"  "+fmt.Sprintf("%*d", countWidth, len(item.Discoveries)))
	}
	return strings.Join(lines, "\n")
}

func truncateDisplay(value string, width int) string {
	if lipgloss.Width(value) <= width {
		return value
	}
	runes := []rune(value)
	if width <= 1 {
		return string(runes[:min(len(runes), width)])
	}
	return string(runes[:min(len(runes), width-1)]) + "…"
}
func subcategoryList(items []string, selected int) string {
	var lines []string
	arrow := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	selectedName := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	for i, item := range items {
		marker := "  "
		if i == selected {
			marker = arrow.Render("▸") + " "
		}
		if i == selected {
			item = selectedName.Render(item)
		}
		lines = append(lines, marker+item)
	}
	return strings.Join(lines, "\n")
}
func discoveryList(items []discovery, selected int) string {
	var lines []string
	arrow := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	selectedName := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	for i, item := range items {
		marker := "  "
		if i == selected {
			marker = arrow.Render("▸") + " "
		}
		name := item.Title
		if i == selected {
			name = selectedName.Render(name)
		}
		status := firstNonEmpty(item.Verification, "unknown")
		lines = append(lines, marker+name+"  "+statusStyle(status).Render(status))
	}
	return strings.Join(lines, "\n")
}
func categoryPreview(items []category, selected int) string {
	if len(items) == 0 {
		return "No meaningful categories were persisted for this scan."
	}
	item := items[selected]
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%s\n\nLogical discoveries: %d\n\n", item.Name, item.Description, len(item.Discoveries))
	for i, d := range item.Discoveries {
		if i == 8 {
			break
		}
		fmt.Fprintf(&b, "%s\n  %s · %s\n  %s\n\n", d.Title, firstNonEmpty(d.MaterialType, "finding"), statusStyle(d.Verification).Render(firstNonEmpty(d.Verification, "unknown")), firstNonEmpty(d.Path, "source not persisted"))
	}
	return b.String()
}
func subcategoryPreview(item category, subs []string, selected int) string {
	if len(subs) == 0 {
		return "No subcategories are available."
	}
	return fmt.Sprintf("%s\n\n%d logical discoveries", subs[selected], len(subcategoryDiscoveries(item, subs[selected])))
}
func statusStyle(value string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "confirmed", "actionable":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	case "review", "weak-review", "uncertain":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	}
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

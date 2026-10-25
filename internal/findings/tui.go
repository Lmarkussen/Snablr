package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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
	Title, Subcategory, MaterialType, Identity, Domain   string
	MaterialFamily, SourceContext                        string
	OriginType                                           string
	Value, Host, Share, Path, Confidence, Verification   string
	KeyFormat, KeyAlgorithm, KeyStatus                   string
	Encrypted                                            bool
	RecoveredPassword                                    string
	Reason                                               string
	PairingStatus, PairingBasis, OriginalVerification    string
	ConnectionDetails                                    []connectionDetail
	Evidence                                             []string
	CorrelationKey, CorrelationType, CorrelationIdentity string
	CorrelationDomain, CorrelationConfidenceRationale    string
	CorrelationSources                                   []credentialanalysis.CorrelationSource
	CorrelationParsed                                    bool
	Sources                                              []string
	PersistedRefs                                        []string
	FindingRef                                           string
	Finding                                              *scanner.Finding
}

type connectionDetail struct {
	Label string
	Value string
}

type category struct {
	Name, Description string
	Discoveries       []discovery
}

type scanLoadedMsg struct {
	scanID       string
	findings     []Finding
	credentials  []Credential
	correlations []Correlation
	categories   []category
	audit        ProjectionAudit
	elapsed      time.Duration
	complete     bool
	partial      bool
	totals       ScanCounts
	err          error
}

type browseLoadedMsg struct {
	scanID           string
	start            browseCursor
	findings         []Finding
	credentials      []Credential
	correlations     []Correlation
	findingCount     int
	credentialCount  int
	correlationCount int
	complete         bool
	err              error
}

type browseCursor struct {
	finding     int64
	credential  int64
	correlation string
}

type searchPageLoadedMsg struct {
	scanID string
	query  string
	start  searchCursor
	page   SearchPage
	err    error
}

type searchCursor struct {
	finding     int64
	credential  int64
	correlation string
}

const (
	evidenceCacheLimit = 32
	evidenceCacheBytes = 8 << 20
)

type evidenceCacheItem struct {
	key         string
	finding     *scanner.Finding
	candidate   *credentialanalysis.Candidate
	correlation string
	size        int
}

type model struct {
	provider                *Provider
	ctx                     context.Context
	output                  io.Writer
	scans                   []Scan
	selectedScan            int
	selectingScan           bool
	screen                  screen
	focus                   int
	selected                int
	selectedSub             int
	selectedDisc            int
	categories              []category
	allMaterial             category
	subs                    []string
	discoveries             []discovery
	findings                []Finding
	width, height           int
	list, preview           viewport.Model
	previewHeight           int
	status                  string
	filter                  string
	filterMode              bool
	discoveryTotal          int
	discoverySource         []discovery
	loading                 bool
	browseLoading           bool
	accountingComplete      bool
	totals                  ScanCounts
	loadError               string
	loadedFindings          []Finding
	loadedCreds             []Credential
	loadedCorrs             []Correlation
	findingCursor           int64
	credentialCursor        int64
	correlationCursor       string
	findingsDone            bool
	credentialsDone         bool
	correlationsDone        bool
	browseStart             browseCursor
	browseHistory           []browseCursor
	searchQuery             string
	searchFindingCursor     int64
	searchCredentialCursor  int64
	searchCorrelationCursor string
	searchDone              bool
	searchLoading           bool
	searchStart             searchCursor
	searchHistory           []searchCursor
	evidenceCache           map[string]evidenceCacheItem
	evidenceOrder           []string
	evidenceBytes           int
	profiler                *finderProfiler
}

type RunOptions struct {
	ProfileDir string
}

// Run starts the offline viewer. It only queries the supplied read-only provider.
func Run(ctx context.Context, provider *Provider, scans []Scan, output io.Writer) error {
	return RunWithOptions(ctx, provider, scans, output, RunOptions{})
}

func RunWithOptions(ctx context.Context, provider *Provider, scans []Scan, output io.Writer, options RunOptions) error {
	if len(scans) == 0 {
		return fmt.Errorf("findings database contains no scan records")
	}
	profiler, err := newFinderProfiler(options.ProfileDir)
	if err != nil {
		return err
	}
	if profiler != nil {
		defer profiler.close()
	}
	loadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := &model{provider: provider, ctx: loadCtx, output: output, scans: scans, profiler: profiler, selectingScan: len(scans) > 1, loading: len(scans) == 1, evidenceCache: make(map[string]evidenceCacheItem), list: viewport.New(1, 1), preview: viewport.New(1, 1)}
	program := tea.NewProgram(m, tea.WithOutput(output), tea.WithAltScreen())
	_, err = program.Run()
	return err
}

func (m *model) loadScan() error {
	scanID := m.scans[m.selectedScan].ID
	totals, err := m.provider.Counts(m.ctx, scanID)
	if err != nil {
		return err
	}
	findings, err := m.provider.FindingsAfter(m.ctx, scanID, 0, PageSize)
	if err != nil {
		return err
	}
	credentials, err := m.provider.CredentialsAfter(m.ctx, scanID, 0, PageSize)
	if err != nil {
		return err
	}
	correlations, err := m.provider.CorrelationsAfter(m.ctx, scanID, "", PageSize)
	if err != nil {
		return err
	}
	m.findings = findings
	credentials, err = expandCredentialGroups(m.ctx, m.provider, scanID, credentials)
	if err != nil {
		return err
	}
	categories, audit := buildCategoriesWithAccounting(scanID, credentials, findings, correlations)
	if audit.UnaccountedRows != 0 {
		return fmt.Errorf("findings projection accounting failed: %d unaccounted rows (%s)", audit.UnaccountedRows, strings.Join(audit.UnaccountedRefs, ", "))
	}
	m.categories = categories
	m.allMaterial = buildAllPersistedMaterial(categories)
	m.selected, m.selectedSub, m.selectedDisc = 0, 0, 0
	m.filter = ""
	m.filterMode = false
	m.screen = screenCategories
	m.totals = totals
	m.accountingComplete = len(findings) >= totals.Findings && len(credentials) >= totals.Credentials && len(correlations) >= totals.Correlations
	m.status = fmt.Sprintf("Initial page: %d/%d findings · %d/%d credentials · %d/%d correlations", len(findings), totals.Findings, len(credentials), totals.Credentials, len(correlations), totals.Correlations)
	m.refresh()
	return nil
}

func (m *model) loadScanCmd() tea.Cmd {
	scanID := m.scans[m.selectedScan].ID
	findingCursor, credentialCursor, correlationCursor := m.findingCursor, m.credentialCursor, m.correlationCursor
	findingsDone, credentialsDone, correlationsDone := m.findingsDone, m.credentialsDone, m.correlationsDone
	return func() tea.Msg {
		started := time.Now()
		totals, err := m.provider.Counts(m.ctx, scanID)
		if err != nil {
			return scanLoadedMsg{scanID: scanID, elapsed: time.Since(started), err: err}
		}
		var findings []Finding
		for page := 0; page < 1 && !findingsDone; page++ {
			rows, err := m.provider.FindingsAfter(m.ctx, scanID, findingCursor, PageSize)
			if err != nil {
				return scanLoadedMsg{scanID: scanID, elapsed: time.Since(started), err: err}
			}
			findings = append(findings, rows...)
			if len(rows) > 0 {
				findingCursor = rows[len(rows)-1].ID
			}
			if len(rows) < PageSize {
				findingsDone = true
			}
		}
		var credentials []Credential
		for page := 0; page < 1 && !credentialsDone; page++ {
			rows, err := m.provider.CredentialsAfter(m.ctx, scanID, credentialCursor, PageSize)
			if err != nil {
				return scanLoadedMsg{scanID: scanID, elapsed: time.Since(started), err: err}
			}
			credentials = append(credentials, rows...)
			if len(rows) > 0 {
				credentialCursor = rows[len(rows)-1].ID
			}
			if len(rows) < PageSize {
				credentialsDone = true
			}
		}
		var correlations []Correlation
		for page := 0; page < 1 && !correlationsDone; page++ {
			rows, err := m.provider.CorrelationsAfter(m.ctx, scanID, correlationCursor, PageSize)
			if err != nil {
				return scanLoadedMsg{scanID: scanID, elapsed: time.Since(started), err: err}
			}
			correlations = append(correlations, rows...)
			if len(rows) > 0 {
				correlationCursor = rows[len(rows)-1].Key
			}
			if len(rows) < PageSize {
				correlationsDone = true
			}
		}
		credentials, err = expandCredentialGroups(m.ctx, m.provider, scanID, credentials)
		if err != nil {
			return scanLoadedMsg{scanID: scanID, elapsed: time.Since(started), err: err}
		}
		return scanLoadedMsg{scanID: scanID, findings: findings, credentials: credentials, correlations: correlations, complete: true, partial: !(findingsDone && credentialsDone && correlationsDone), totals: totals, elapsed: time.Since(started)}
	}
}

func (m *model) applyScanLoaded(msg scanLoadedMsg) tea.Cmd {
	if msg.scanID != m.scans[m.selectedScan].ID {
		return nil
	}
	if msg.err != nil {
		m.loading = false
		m.loadError = msg.err.Error()
		m.status = "Load failed: " + m.loadError
		m.refresh()
		return nil
	}
	m.loadedFindings = append(m.loadedFindings, msg.findings...)
	m.loadedCreds = append(m.loadedCreds, msg.credentials...)
	m.loadedCorrs = append(m.loadedCorrs, msg.correlations...)
	if len(msg.findings) > 0 {
		m.findingCursor = msg.findings[len(msg.findings)-1].ID
	}
	if len(msg.credentials) > 0 {
		m.credentialCursor = msg.credentials[len(msg.credentials)-1].ID
	}
	if len(msg.correlations) > 0 {
		m.correlationCursor = msg.correlations[len(msg.correlations)-1].Key
	}
	if err := m.profiler.stage(fmt.Sprintf("batch-%06d-preprojection", len(m.loadedFindings)), len(m.loadedFindings), len(m.loadedCreds), len(m.loadedCorrs), false); err != nil {
		m.loading = false
		m.loadError = err.Error()
		m.status = "Profile failed: " + m.loadError
		m.refresh()
		return nil
	}
	if !msg.partial && len(msg.findings) < PageSize {
		m.findingsDone = true
	}
	if !msg.partial && len(msg.credentials) < PageSize {
		m.credentialsDone = true
	}
	if !msg.partial && len(msg.correlations) < PageSize {
		m.correlationsDone = true
	}
	if !msg.complete {
		m.categories = nil
		m.allMaterial = category{}
		m.findings = nil
		m.loading = true
		m.status = fmt.Sprintf("Loading persisted observations: %d findings, %d credentials, %d correlations", len(m.loadedFindings), len(m.loadedCreds), len(m.loadedCorrs))
		m.refresh()
		return m.loadScanCmd()
	}
	categories, audit := buildCategoriesWithAccounting(m.scans[m.selectedScan].ID, m.loadedCreds, m.loadedFindings, m.loadedCorrs)
	if msg.categories != nil {
		categories, audit = msg.categories, msg.audit
	}
	m.categories = categories
	m.allMaterial = buildAllPersistedMaterial(categories)
	m.selected, m.selectedSub, m.selectedDisc = 0, 0, 0
	m.screen = screenCategories
	m.loading = false
	m.accountingComplete = !msg.partial
	m.totals = msg.totals
	if audit.UnaccountedRows != 0 {
		m.loadError = fmt.Sprintf("findings projection accounting failed: %d unaccounted rows (%s)", audit.UnaccountedRows, strings.Join(audit.UnaccountedRefs, ", "))
		m.status = "Load failed: " + m.loadError
		m.refresh()
		return nil
	}
	m.loadError = ""
	m.filter = ""
	m.filterMode = false
	findingCount, credentialCount, correlationCount := len(m.loadedFindings), len(m.loadedCreds), len(m.loadedCorrs)
	compactDiscoveries(m.categories)
	compactDiscoveries([]category{m.allMaterial})
	m.loadedFindings = nil
	m.loadedCreds = nil
	m.loadedCorrs = nil
	m.findings = nil
	if err := m.profiler.stage("final-postcompaction", findingCount, credentialCount, correlationCount, true); err != nil {
		m.loadError = err.Error()
		m.status = "Profile failed: " + m.loadError
	}
	if msg.partial {
		m.status = fmt.Sprintf("Initial page: %d/%d findings · %d/%d credentials · %d/%d correlations · totals/accounting pending · %s", findingCount, msg.totals.Findings, credentialCount, msg.totals.Credentials, correlationCount, msg.totals.Correlations, msg.elapsed.Round(time.Millisecond))
	} else {
		m.status = fmt.Sprintf("%d categories · %d findings · %d logical credentials · %d correlations · loaded in %s", len(m.categories), findingCount, audit.LogicalDiscoveryCount, correlationCount, msg.elapsed.Round(time.Millisecond))
	}
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

// expandCredentialGroups adds bounded persisted relationship context before
// projection. The canonical representative remains the lowest persisted row
// ID; rows fetched only as context are grouped into that representative and
// are not retained as a second full projection.
func expandCredentialGroups(ctx context.Context, provider *Provider, scanID string, credentials []Credential) ([]Credential, error) {
	if provider == nil || len(credentials) == 0 {
		return credentials, nil
	}
	result := append([]Credential(nil), credentials...)
	seenRows := make(map[string]struct{}, len(result))
	seenGroups := make(map[string]struct{}, len(credentials))
	for _, item := range credentials {
		rowRef := credentialRowRef(item)
		seenRows[rowRef] = struct{}{}
		groupKey := credentialGroupKey(item.Candidate)
		if _, done := seenGroups[groupKey]; done || groupKey == "\x00\x00\x00\x00" {
			continue
		}
		seenGroups[groupKey] = struct{}{}
		related, err := provider.RelatedCredentialsAfter(ctx, scanID, item, 0, PageSize)
		if err != nil {
			return nil, err
		}
		for _, relatedItem := range related {
			ref := credentialRowRef(relatedItem)
			if _, exists := seenRows[ref]; exists {
				continue
			}
			seenRows[ref] = struct{}{}
			result = append(result, relatedItem)
		}
	}
	return result, nil
}

func credentialGroupKey(candidate credentialanalysis.Candidate) string {
	logicalType, logicalIdentity, logicalValue := candidate.CredentialType, candidate.Identity, candidate.Value
	if pair, ok := deriveConnectionPair(candidate); ok {
		logicalType, logicalIdentity, logicalValue = "password", pair.Username, pair.Password
	}
	return strings.Join([]string{logicalType, logicalIdentity, candidate.Domain, logicalValue}, "\x00")
}

func retainCanonicalCredentialGroups(expanded, page []Credential) []Credential {
	pageRows := make(map[string]struct{}, len(page))
	for _, item := range page {
		pageRows[credentialGroupKey(item.Candidate)] = struct{}{}
	}
	minimum := make(map[string]int64, len(expanded))
	for _, item := range expanded {
		key := credentialGroupKey(item.Candidate)
		if current, ok := minimum[key]; !ok || item.ID < current {
			minimum[key] = item.ID
		}
	}
	canonicalRows := make(map[string]struct{}, len(pageRows))
	for _, item := range page {
		key := credentialGroupKey(item.Candidate)
		if item.ID == minimum[key] {
			canonicalRows[key] = struct{}{}
		}
	}
	result := make([]Credential, 0, len(expanded))
	for _, item := range expanded {
		if _, ok := canonicalRows[credentialGroupKey(item.Candidate)]; ok {
			result = append(result, item)
		}
	}
	return result
}

func buildCategoriesWithAccounting(scanID string, credentials []Credential, findings []Finding, correlations []Correlation) ([]category, ProjectionAudit) {
	ordered := []struct {
		name, description string
	}{
		{"Credentials", "Confirmed and review-level plaintext credential material"},
		{"Keys & Certificates", "Validated private-key and certificate material"},
		{"Hashes & Captures", "Validated NT hash and NetNTLM capture material"},
		{"Database Locations & Connections", "Observed database files, endpoints, and configuration"},
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
		displayCandidate := candidate
		connectionPair, hasConnectionPair := deriveConnectionPair(candidate)
		if hasConnectionPair {
			displayCandidate.Identity = connectionPair.Username
		}
		pairing := interpretCredential(candidate)
		name, sub := classifyCandidate(candidate)
		// Group by the logical credential when a connection string explicitly
		// contains a username/password pair. The original connection-string
		// value remains on the representative and every contributing row is
		// retained in PersistedRefs and Sources.
		logicalType, logicalIdentity, logicalValue := candidate.CredentialType, candidate.Identity, candidate.Value
		if hasConnectionPair {
			logicalType, logicalIdentity, logicalValue = "password", connectionPair.Username, connectionPair.Password
		}
		key := strings.Join([]string{logicalType, logicalIdentity, candidate.Domain, logicalValue}, "\x00")
		rowRef := credentialRowRef(item)
		if key == "\x00\x00\x00" || strings.TrimSpace(candidate.Value) == "" {
			key = rowRef
		}
		if ref, ok := seen[key]; ok {
			group := groups[ref.category]
			group.Discoveries[ref.index].PersistedRefs = appendUnique(group.Discoveries[ref.index].PersistedRefs, rowRef)
			group.Discoveries[ref.index].Sources = appendUnique(group.Discoveries[ref.index].Sources, sourceLabel(candidate))
			group.Discoveries[ref.index].SourceContext = appendContext(group.Discoveries[ref.index].SourceContext, sourceContext(candidate))
			group.Discoveries[ref.index].OriginType = mergeOrigin(group.Discoveries[ref.index].OriginType, originType(candidate))
			if candidate.Value != "" {
				group.Discoveries[ref.index].Evidence = append(group.Discoveries[ref.index].Evidence, candidate.Value)
			}
			continue
		}
		d := discovery{
			Title:                discoveryTitle(displayCandidate),
			Subcategory:          sub,
			MaterialType:         candidate.CredentialType,
			Identity:             displayCandidate.Identity,
			Domain:               candidate.Domain,
			Value:                candidate.Value,
			RecoveredPassword:    connectionPair.Password,
			Host:                 candidate.Host,
			Share:                candidate.Share,
			Path:                 candidate.Path,
			Confidence:           string(candidate.Verification),
			KeyFormat:            candidate.KeyFormat,
			KeyAlgorithm:         candidate.KeyAlgorithm,
			KeyStatus:            candidate.KeyStatus,
			Encrypted:            candidate.Encrypted,
			Verification:         firstNonEmpty(pairing.Status, string(candidate.Verification)),
			PairingStatus:        pairing.Status,
			PairingBasis:         pairing.Basis,
			OriginalVerification: pairing.OriginalVerification,
			MaterialFamily:       name,
			SourceContext:        sourceContext(candidate),
			OriginType:           originType(candidate),
			Reason:               strings.Join(candidate.ReviewReasons, "; "),
			ConnectionDetails:    connectionDetails(candidate),
			Evidence:             uniqueNonEmpty([]string{candidate.Value}),
			Sources:              []string{sourceLabel(candidate)},
			PersistedRefs:        []string{rowRef},
		}
		group := groups[name]
		seen[key] = discoveryRef{category: name, index: len(group.Discoveries)}
		group.Discoveries = append(group.Discoveries, d)
	}
	for _, item := range findings {
		f := item.Finding
		if windowsArtifactFinding(f) {
			name := "Windows & Deployment Artifacts"
			group := groups[name]
			group.Discoveries = append(group.Discoveries, discovery{
				Title:          firstNonEmpty(f.RuleName, f.RuleID),
				Subcategory:    windowsArtifactSubcategory(f),
				MaterialFamily: name,
				MaterialType:   "Windows artifact observation",
				Host:           f.Host,
				Share:          f.Share,
				Path:           f.FilePath,
				Confidence:     firstNonEmpty(f.Confidence, "unknown"),
				Verification:   firstNonEmpty(f.TriageClass, f.SignalType, "observed"),
				Reason:         f.MatchReason,
				Sources:        []string{sourceLabelFinding(f)}, PersistedRefs: []string{findingRowRef(item)},
				FindingRef: findingRowRef(item),
			})
			continue
		}
		if applicationCloudFinding(f) {
			name := "Application & Cloud Secrets"
			group := groups[name]
			group.Discoveries = append(group.Discoveries, discovery{
				Title:          firstNonEmpty(f.RuleName, f.RuleID),
				Subcategory:    applicationCloudSubcategory(f),
				MaterialFamily: name,
				MaterialType:   "application/cloud observation",
				Host:           f.Host,
				Share:          f.Share,
				Path:           f.FilePath,
				Confidence:     firstNonEmpty(f.Confidence, "unknown"),
				Verification:   firstNonEmpty(f.TriageClass, f.SignalType, "observed"),
				Reason:         f.MatchReason,
				Sources:        []string{sourceLabelFinding(f)}, PersistedRefs: []string{findingRowRef(item)},
				FindingRef: findingRowRef(item),
			})
			continue
		}
		if databaseLocationFinding(f) {
			name := "Database Locations & Connections"
			group := groups[name]
			group.Discoveries = append(group.Discoveries, discovery{
				Title:          firstNonEmpty(f.RuleName, f.RuleID),
				Subcategory:    databaseLocationSubcategory(f),
				MaterialFamily: name,
				MaterialType:   "database observation",
				Host:           f.Host,
				Share:          f.Share,
				Path:           f.FilePath,
				Confidence:     firstNonEmpty(f.Confidence, "unknown"),
				Verification:   firstNonEmpty(f.TriageClass, f.SignalType, "observed"),
				Reason:         f.MatchReason,
				Sources:        []string{sourceLabelFinding(f)}, PersistedRefs: []string{findingRowRef(item)},
				FindingRef: findingRowRef(item),
			})
			continue
		}
		if !f.Actionable && !strings.EqualFold(f.TriageClass, "review") {
			groups["Original Findings"].Discoveries = append(groups["Original Findings"].Discoveries, discovery{
				Title: firstNonEmpty(f.RuleName, f.RuleID), Subcategory: "Supporting Findings", MaterialType: "supporting finding",
				Host: f.Host, Share: f.Share, Path: f.FilePath, Confidence: firstNonEmpty(f.Confidence, "unknown"), Verification: "supporting",
				Sources: []string{sourceLabelFinding(f)}, PersistedRefs: []string{findingRowRef(item)}, FindingRef: findingRowRef(item),
			})
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
			Sources:        []string{sourceLabelFinding(f)}, PersistedRefs: []string{findingRowRef(item)},
			FindingRef: findingRowRef(item),
		})
	}
	for _, item := range correlations {
		var record credentialanalysis.Correlation
		parsed := json.Unmarshal([]byte(item.Payload), &record) == nil
		title := correlationTitle(item.Key, record, parsed)
		groups["Correlations"].Discoveries = append(groups["Correlations"].Discoveries, discovery{
			Title: title, Subcategory: "Cross-file Relationships", MaterialType: "correlation", Value: item.Payload, Evidence: []string{item.Payload},
			Verification: "persisted correlation", Confidence: firstNonEmpty(record.Confidence, "contextual"),
			CorrelationKey: item.Key, CorrelationType: record.Type, CorrelationIdentity: record.Identity,
			CorrelationDomain: record.Domain, CorrelationConfidenceRationale: record.ConfidenceRationale,
			CorrelationSources: append([]credentialanalysis.CorrelationSource(nil), record.Sources...), CorrelationParsed: parsed,
			PersistedRefs: []string{correlationRowRef(item)},
		})
	}
	result := make([]category, 0, len(ordered))
	for _, item := range ordered {
		if group := groups[item.name]; len(group.Discoveries) > 0 {
			result = append(result, *group)
		}
	}
	return result, auditProjection(scanID, credentials, findings, correlations, result)
}

func applicationCloudFinding(f scanner.Finding) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.RuleID)), "cloudinspect.")
}

func windowsArtifactFinding(f scanner.Finding) bool {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	return strings.HasPrefix(ruleID, "windowsinspect.") || strings.HasPrefix(ruleID, "sccminspect.")
}

func windowsArtifactSubcategory(f scanner.Finding) string {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	switch {
	case strings.Contains(ruleID, "sccminspect") && strings.Contains(ruleID, "distribution_point"):
		return "SCCM Infrastructure & Distribution Points"
	case strings.Contains(ruleID, "sccminspect") && strings.Contains(ruleID, "task_sequence"):
		return "SCCM Packages & Task Sequences"
	case strings.Contains(ruleID, "sccminspect") && strings.Contains(ruleID, "deployment"):
		return "SCCM Deployment References"
	case strings.Contains(ruleID, "sccminspect"):
		return "SCCM Site & Client Configuration"
	case strings.Contains(ruleID, "unattend"):
		return "Windows Setup & Unattend"
	case strings.Contains(ruleID, "scheduled_task"):
		return "Windows Scheduled Tasks"
	case strings.Contains(ruleID, "gpp"):
		return "Group Policy & Preferences"
	case strings.Contains(ruleID, "registry_export"):
		return "Registry Exports"
	default:
		return "Windows Setup & Unattend"
	}
}

func applicationCloudSubcategory(f scanner.Finding) string {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	switch {
	case strings.HasPrefix(ruleID, "cloudinspect.aws."):
		return "AWS Credentials"
	case strings.HasPrefix(ruleID, "cloudinspect.azure."):
		return "Azure / Entra Credentials"
	case strings.HasPrefix(ruleID, "cloudinspect.gcp.external_account"):
		return "Secret References & Configuration Artifacts"
	case strings.HasPrefix(ruleID, "cloudinspect.gcp."):
		return "Google Cloud Credentials"
	default:
		return "Other Cloud Provider Credentials"
	}
}

func databaseLocationFinding(f scanner.Finding) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.RuleID)), "dbinspect.")
}

func databaseLocationSubcategory(f scanner.Finding) string {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	switch {
	case strings.Contains(ruleID, "structured_config"):
		return "Database Servers & Instances"
	case strings.Contains(ruleID, "connection") || strings.Contains(ruleID, "jdbc") || strings.Contains(ruleID, "url"):
		return "Database Connection Strings"
	case strings.Contains(ruleID, "tns") || strings.Contains(ruleID, "server") || strings.Contains(ruleID, "endpoint"):
		return "Database Servers & Instances"
	case strings.Contains(ruleID, "odbc") || strings.Contains(ruleID, "udl") || strings.Contains(ruleID, "dsn"):
		return "DSN/ODBC Configurations"
	case strings.Contains(ruleID, "artifact") && (strings.Contains(ruleID, "tns") || strings.Contains(ruleID, "sqlnet") || strings.Contains(ruleID, "ini")):
		return "Database Configuration Artifacts"
	case strings.Contains(ruleID, "artifact") || strings.Contains(ruleID, "backup"):
		return "Database Files & Backups"
	default:
		return "Database Configuration Artifacts"
	}
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
	case "kerberos_asrep":
		return "Hashes & Captures", "Kerberos AS-REP"
	case "kerberos_tgs":
		return "Hashes & Captures", "Kerberos TGS"
	case "dcc":
		return "Hashes & Captures", "DCC1"
	case "dcc2":
		return "Hashes & Captures", "DCC2"
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
		return connectionPairOrigin(candidate)
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

func connectionDetails(candidate credentialanalysis.Candidate) []connectionDetail {
	typ := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	if typ != "connection_string" && typ != "dsn" {
		return nil
	}
	if pair, ok := parseDatabaseURI(strings.TrimSpace(candidate.Value)); ok {
		details := []connectionDetail{{Label: "Provider / Driver", Value: pair.Provider}, {Label: "Server / Host", Value: pair.Server}}
		if pair.Port != "" {
			details = append(details, connectionDetail{Label: "Port", Value: pair.Port})
		}
		if pair.Database != "" {
			details = append(details, connectionDetail{Label: "Database / Catalog", Value: pair.Database})
		}
		details = append(details, connectionDetail{Label: "Username", Value: pair.Username}, connectionDetail{Label: "Password", Value: pair.Password})
		return details
	}
	var details []connectionDetail
	for _, field := range splitConnectionFields(candidate.Value) {
		label := connectionFieldLabel(field.Key)
		if label == "" || strings.TrimSpace(field.Value) == "" {
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
			details = append(details, connectionDetail{Label: label, Value: field.Value})
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
	case "port":
		return "Port"
	default:
		return ""
	}
}

func reviewSubcategory(candidate credentialanalysis.Candidate) string {
	if strings.EqualFold(candidate.CredentialType, "private_key") {
		if candidate.Encrypted || strings.EqualFold(candidate.KeyStatus, "encrypted") {
			return "Encrypted Private Keys"
		}
		if strings.EqualFold(candidate.KeyStatus, "malformed") {
			return "Malformed Key Candidates"
		}
		return "Private Keys — Review"
	}
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
	if strings.Contains(strings.ToLower(candidate.KeyFormat), "openssh") || strings.Contains(strings.ToLower(candidate.KeyAlgorithm), "openssh") || strings.Contains(value, "openssh") || strings.Contains(value, "begin ssh") {
		return "OpenSSH Keys"
	}
	if strings.Contains(strings.ToLower(candidate.KeyAlgorithm), "rsa") || strings.Contains(value, "begin rsa") {
		return "RSA Keys"
	}
	if strings.Contains(strings.ToLower(candidate.KeyFormat), "pem") {
		return "PEM Keys"
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
	label := fmt.Sprintf("\\\\%s\\%s\\%s", f.Host, f.Share, strings.TrimPrefix(f.FilePath, `/`))
	if f.ArchiveMemberPath != "" {
		label += "!" + f.ArchiveMemberPath
	}
	return label
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (m *model) Init() tea.Cmd {
	if m.loading {
		return m.loadScanCmd()
	}
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case scanLoadedMsg:
		cmd := m.applyScanLoaded(msg)
		if m.width > 0 && m.height > 0 {
			m.resize()
		}
		return m, cmd
	case browseLoadedMsg:
		m.applyBrowseLoaded(msg)
		if m.width > 0 && m.height > 0 {
			m.resize()
		}
		return m, nil
	case searchPageLoadedMsg:
		m.applySearchPage(msg)
		if m.width > 0 && m.height > 0 {
			m.resize()
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
	case tea.KeyMsg:
		if m.loading {
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m, nil
		}
		if m.filterMode {
			m.handleFilterKey(msg)
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c":
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
			return m, m.page(1)
		case "/":
			if m.screen == screenDiscoveries {
				m.filterMode = true
				m.status = "Filter: " + m.filter
			}
		case "enter", "right":
			if m.focus == 0 {
				return m, m.open()
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
		if delta < 0 {
			m.preview.LineUp(-delta)
		} else {
			m.preview.LineDown(delta)
		}
		return
	}
	switch m.screen {
	case screenCategories:
		m.selected = clamp(m.selected+delta, 0, len(m.categoryItems())-1)
	case screenSubcategories:
		m.selectedSub = clamp(m.selectedSub+delta, 0, len(m.subs)-1)
	case screenDiscoveries:
		m.selectedDisc = clamp(m.selectedDisc+delta, 0, len(m.discoveries)-1)
	}
	m.refresh()
}

func (m *model) page(direction int) tea.Cmd {
	if direction > 0 && m.screen == screenDiscoveries && m.selectedDisc >= len(m.discoveries)-1 && strings.TrimSpace(m.filter) != "" && !m.searchLoading && !m.searchDone {
		m.searchHistory = append(m.searchHistory, m.searchStart)
		m.searchStart = searchCursor{finding: m.searchFindingCursor, credential: m.searchCredentialCursor, correlation: m.searchCorrelationCursor}
		m.searchLoading = true
		m.status = "Loading next matching page..."
		m.refresh()
		return m.loadSearchPageCmd()
	}
	if direction < 0 && m.screen == screenDiscoveries && m.selectedDisc == 0 && !m.searchLoading && len(m.searchHistory) > 0 && strings.TrimSpace(m.filter) != "" {
		last := len(m.searchHistory) - 1
		m.searchStart = m.searchHistory[last]
		m.searchHistory = m.searchHistory[:last]
		m.searchLoading = true
		m.status = "Loading previous matching page..."
		m.refresh()
		return m.loadSearchPageCmd()
	}
	if direction > 0 && m.screen == screenDiscoveries && m.selectedDisc >= len(m.discoveries)-1 && !m.browseLoading && !m.findingsDone {
		m.browseHistory = append(m.browseHistory, m.browseStart)
		m.browseStart = browseCursor{finding: m.findingCursor, credential: m.credentialCursor, correlation: m.correlationCursor}
		m.browseLoading = true
		m.status = "Loading next indexed page..."
		m.refresh()
		return m.loadBrowsePageCmd()
	}
	if direction < 0 && m.screen == screenDiscoveries && m.selectedDisc == 0 && !m.browseLoading && len(m.browseHistory) > 0 && strings.TrimSpace(m.filter) == "" {
		last := len(m.browseHistory) - 1
		m.browseStart = m.browseHistory[last]
		m.browseHistory = m.browseHistory[:last]
		m.browseLoading = true
		m.status = "Loading previous indexed page..."
		m.refresh()
		return m.loadBrowsePageCmd()
	}
	if m.focus == 1 {
		if direction < 0 {
			m.preview.PageUp()
		} else {
			m.preview.PageDown()
		}
		return nil
	}
	m.move(direction * 8)
	return nil
}

func (m *model) loadSearchPageCmd() tea.Cmd {
	scanID := m.scans[m.selectedScan].ID
	query := strings.TrimSpace(m.filter)
	start := m.searchStart
	findingCursor, credentialCursor := start.finding, start.credential
	correlationCursor := start.correlation
	return func() tea.Msg {
		page, err := m.provider.SearchPageAfter(m.ctx, scanID, query, findingCursor, credentialCursor, correlationCursor, PageSize)
		return searchPageLoadedMsg{scanID: scanID, query: query, start: start, page: page, err: err}
	}
}

func (m *model) applySearchPage(msg searchPageLoadedMsg) {
	m.searchLoading = false
	m.searchStart = msg.start
	if msg.scanID != m.scans[m.selectedScan].ID || msg.query != strings.TrimSpace(m.filter) || msg.query != m.searchQuery {
		return
	}
	if msg.err != nil {
		m.status = "Search failed: " + msg.err.Error()
		m.refresh()
		return
	}
	m.searchFindingCursor = msg.page.FindingCursor
	m.searchCredentialCursor = msg.page.CredentialCursor
	m.searchCorrelationCursor = msg.page.CorrelationCursor
	m.searchDone = msg.page.Done
	if err := m.setSearchDiscoveries(msg.page); err != nil {
		m.status = "Search relationship expansion failed: " + err.Error()
	}
	m.refresh()
}

func (m *model) setSearchDiscoveries(page SearchPage) error {
	expandedCredentials, err := expandCredentialGroups(m.ctx, m.provider, m.scans[m.selectedScan].ID, page.Credentials)
	if err != nil {
		return err
	}
	page.Credentials = expandedCredentials
	searchCategories, _ := buildCategoriesWithAccounting(m.scans[m.selectedScan].ID, page.Credentials, page.Findings, page.Correlations)
	items := m.categoryItems()
	if m.selected < 0 || m.selected >= len(items) || len(m.subs) == 0 {
		m.discoverySource = nil
		m.discoveries = nil
		return nil
	}
	wantedCategory := items[m.selected].Name
	if wantedCategory == "All Persisted Material" {
		searchCategories = []category{buildAllPersistedMaterial(searchCategories)}
	}
	for _, item := range searchCategories {
		if item.Name == wantedCategory {
			m.discoverySource = subcategoryDiscoveries(item, m.subs[m.selectedSub])
			m.discoveries = append([]discovery(nil), m.discoverySource...)
			m.selectedDisc = 0
			m.discoveryTotal = page.PersistedRows
			return nil
		}
	}
	m.discoverySource = nil
	m.discoveries = nil
	m.discoveryTotal = page.PersistedRows
	return nil
}

func (m *model) loadBrowsePageCmd() tea.Cmd {
	scanID := m.scans[m.selectedScan].ID
	start := m.browseStart
	findingCursor, credentialCursor, correlationCursor := start.finding, start.credential, start.correlation
	return func() tea.Msg {
		findings, err := m.provider.FindingsAfter(m.ctx, scanID, findingCursor, PageSize)
		if err != nil {
			return browseLoadedMsg{scanID: scanID, start: start, err: err}
		}
		credentials, err := m.provider.CredentialsAfter(m.ctx, scanID, credentialCursor, PageSize)
		if err != nil {
			return browseLoadedMsg{scanID: scanID, start: start, err: err}
		}
		correlations, err := m.provider.CorrelationsAfter(m.ctx, scanID, correlationCursor, PageSize)
		if err != nil {
			return browseLoadedMsg{scanID: scanID, start: start, err: err}
		}
		pageCredentials := credentials
		credentials, err = expandCredentialGroups(m.ctx, m.provider, scanID, credentials)
		if err != nil {
			return browseLoadedMsg{scanID: scanID, start: start, err: err}
		}
		credentials = retainCanonicalCredentialGroups(credentials, pageCredentials)
		return browseLoadedMsg{scanID: scanID, start: start, findings: findings, credentials: credentials, correlations: correlations,
			findingCount: len(findings), credentialCount: len(pageCredentials), correlationCount: len(correlations),
			complete: len(findings) < PageSize && len(pageCredentials) < PageSize && len(correlations) < PageSize}
	}
}

func (m *model) applyBrowseLoaded(msg browseLoadedMsg) {
	if msg.scanID != m.scans[m.selectedScan].ID {
		return
	}
	m.browseLoading = false
	m.browseStart = msg.start
	if msg.err != nil {
		m.status = "Next page failed: " + msg.err.Error()
		m.refresh()
		return
	}
	if len(msg.findings) > 0 {
		m.findingCursor = msg.findings[len(msg.findings)-1].ID
	}
	if len(msg.credentials) > 0 {
		m.credentialCursor = msg.credentials[len(msg.credentials)-1].ID
	}
	if len(msg.correlations) > 0 {
		m.correlationCursor = msg.correlations[len(msg.correlations)-1].Key
	}
	if msg.findingCount < PageSize {
		m.findingsDone = true
	}
	if msg.credentialCount < PageSize {
		m.credentialsDone = true
	}
	if msg.correlationCount < PageSize {
		m.correlationsDone = true
	}
	pageCategories, _ := buildCategoriesWithAccounting(msg.scanID, msg.credentials, msg.findings, msg.correlations)
	items := m.categoryItems()
	if m.selected < 0 || m.selected >= len(items) {
		return
	}
	wanted := items[m.selected].Name
	if wanted == "All Persisted Material" {
		pageCategories = []category{buildAllPersistedMaterial(pageCategories)}
	}
	for _, item := range pageCategories {
		if item.Name != wanted {
			continue
		}
		m.discoverySource = subcategoryDiscoveries(item, m.subs[m.selectedSub])
		m.discoveries = append([]discovery(nil), m.discoverySource...)
		m.selectedDisc = 0
		m.status = fmt.Sprintf("Showing indexed page; totals remain %d findings, %d credentials, %d correlations", m.totals.Findings, m.totals.Credentials, m.totals.Correlations)
		m.refresh()
		return
	}
	m.discoverySource = nil
	m.discoveries = nil
	m.status = "No discoveries in the next indexed page for this category."
	m.refresh()
}

func (m *model) open() tea.Cmd {
	if m.selectingScan {
		m.selectingScan = false
		m.loading = true
		m.loadError = ""
		m.screen = screenCategories
		m.status = "Loading persisted observations..."
		if m.width > 0 && m.height > 0 {
			m.resize()
		} else {
			m.refresh()
		}
		return m.loadScanCmd()
	}
	switch m.screen {
	case screenCategories:
		items := m.categoryItems()
		m.subs = categorySubcategories(items[m.selected])
		m.selectedSub = 0
		m.screen = screenSubcategories
		m.filter = ""
	case screenSubcategories:
		items := m.categoryItems()
		m.discoveries = subcategoryDiscoveries(items[m.selected], m.subs[m.selectedSub])
		m.discoverySource = append(m.discoverySource[:0], m.discoveries...)
		m.selectedDisc = 0
		m.screen = screenDiscoveries
	}
	m.filterMode = false
	m.focus = 0
	if m.width > 0 && m.height > 0 {
		m.resize()
	} else {
		m.refresh()
	}
	return nil
}

func (m *model) back() {
	switch m.screen {
	case screenDiscoveries:
		m.screen = screenSubcategories
		m.filter = ""
	case screenSubcategories:
		m.screen = screenCategories
	default:
		return
	}
	m.focus = 0
	if m.width > 0 && m.height > 0 {
		m.resize()
	} else {
		m.refresh()
	}
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
	if m.loading && len(m.categories) == 0 {
		m.list.SetContent("Loading persisted observations...")
		m.preview.SetContent("The Finder is loading a bounded startup view. Complete evidence and accounting will appear when loading finishes.")
		return
	}
	if m.loadError != "" {
		m.list.SetContent("Unable to load persisted observations.")
		m.preview.SetContent(m.loadError)
		return
	}
	if m.selectingScan {
		m.list.SetContent(scanList(m.scans, m.selectedScan))
		m.preview.SetContent("No scan selected.")
		return
	}
	switch m.screen {
	case screenCategories:
		items := m.categoryItems()
		m.selected = clamp(m.selected, 0, max(0, len(items)-1))
		m.list.SetContent(categoryList(items, m.selected, m.list.Width))
		m.keepListSelectionVisible(m.selected)
		m.preview.SetContent(categoryPreview(items, m.selected))
	case screenSubcategories:
		items := m.categoryItems()
		m.selectedSub = clamp(m.selectedSub, 0, max(0, len(m.subs)-1))
		m.list.SetContent(subcategoryList(m.subs, m.selectedSub))
		m.keepListSelectionVisible(m.selectedSub)
		m.preview.SetContent(subcategoryPreview(items[m.selected], m.subs, m.selectedSub))
	case screenDiscoveries:
		if strings.TrimSpace(m.filter) != "" && m.provider != nil && m.searchQuery != strings.TrimSpace(m.filter) {
			m.searchQuery = strings.TrimSpace(m.filter)
			m.searchFindingCursor, m.searchCredentialCursor, m.searchCorrelationCursor = 0, 0, ""
			m.searchDone = false
			m.searchStart = searchCursor{}
			m.searchHistory = nil
			if page, err := m.provider.SearchPageAfter(m.ctx, m.scans[m.selectedScan].ID, m.searchQuery, 0, 0, "", PageSize); err == nil {
				m.searchFindingCursor = page.FindingCursor
				m.searchCredentialCursor = page.CredentialCursor
				m.searchCorrelationCursor = page.CorrelationCursor
				m.searchDone = page.Done
				if err := m.setSearchDiscoveries(page); err != nil {
					m.status = "Search relationship expansion failed: " + err.Error()
				}
			} else {
				m.status = "Search failed: " + err.Error()
			}
		}
		base := m.discoverySource
		if len(base) == 0 {
			if len(m.subs) > 0 {
				items := m.categoryItems()
				base = subcategoryDiscoveries(items[m.selected], m.subs[m.selectedSub])
			} else {
				base = m.discoveries
			}
		}
		m.discoveryTotal = len(base)
		m.discoveries = filterDiscoveries(base, m.filter)
		if strings.TrimSpace(m.filter) != "" && m.provider != nil {
			m.discoveryTotal = len(m.discoveries)
		}
		m.selectedDisc = clamp(m.selectedDisc, 0, max(0, len(m.discoveries)-1))
		if len(m.discoveries) == 0 {
			m.list.SetContent("No discoveries match the current filter.")
		} else {
			m.list.SetContent(discoveryList(m.discoveries, m.selectedDisc))
		}
		m.keepListSelectionVisible(m.selectedDisc)
		m.preview.GotoTop()
		m.preview.SetContent(wrapDetails(m.evidenceText(), m.preview.Width))
		if strings.TrimSpace(m.filter) != "" && m.provider != nil {
			if m.searchDone {
				m.status = fmt.Sprintf("Showing %d discoveries from complete matching pages", len(m.discoveries))
			} else {
				m.status = fmt.Sprintf("Showing %d discoveries from bounded search page; PageDown continues matches", len(m.discoveries))
			}
		} else {
			m.status = fmt.Sprintf("Showing %d/%d discoveries", len(m.discoveries), m.discoveryTotal)
		}
	}
}

func (m *model) keepListSelectionVisible(selected int) {
	visible := m.list.VisibleLineCount()
	if visible <= 0 {
		return
	}
	offset := m.list.YOffset
	if selected < offset {
		offset = selected
	} else if selected >= offset+visible {
		offset = selected - visible + 1
	}
	m.list.SetYOffset(offset)
}

func (m *model) evidenceText() string {
	if len(m.discoveries) == 0 {
		return "No discovery selected."
	}
	m.hydrateDiscovery(&m.discoveries[m.selectedDisc])
	d := m.discoveries[m.selectedDisc]
	var b strings.Builder
	if d.MaterialType == "correlation" {
		return correlationEvidenceText(d)
	}
	if evidence := discoveryEvidence(d); len(evidence) > 0 {
		section := "OBSERVED EVIDENCE"
		if discoveryIsSecretBearing(d) {
			section = "RECOVERED EVIDENCE"
		}
		fmt.Fprintf(&b, "%s\n", evidenceSectionForDiscovery(section, d))
		for index, value := range evidence {
			if len(evidence) > 1 {
				fmt.Fprintf(&b, "Observation %d\n", index+1)
			}
			b.WriteString(evidenceValueForDiscovery(value, d))
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "%s\n%s\n\nMaterial family: %s\nMaterial type: %s\nVerification: %s\nConfidence: %s\nPersisted rows: %d\nSource observations: %d\n", evidenceSection("DISCOVERY"), d.Title, firstNonEmpty(d.MaterialFamily, "unknown"), firstNonEmpty(d.MaterialType, "unknown"), firstNonEmpty(d.Verification, "unknown"), firstNonEmpty(d.Confidence, "unknown"), len(d.PersistedRefs), len(d.Sources))
	if d.RecoveredPassword != "" && d.Identity != "" {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("USERNAME + PASSWORD COMBINATION"))
		fmt.Fprintf(&b, "%s %s\n%s %s\n", evidenceLabel("Username:"), evidenceValue(qualifiedIdentity(d)), evidencePasswordLabel("Password:"), evidenceValue(d.RecoveredPassword))
		fmt.Fprintf(&b, "Credential kind: database credential\nOrigin type: %s\n", firstNonEmpty(d.OriginType, "Database Credential"))
	} else if d.Value != "" && isUsernamePasswordType(d.MaterialType) && strings.Contains(strings.ToLower(d.PairingStatus), "password only") {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("PASSWORD ONLY — IDENTITY NOT ESTABLISHED"))
		b.WriteString("Pairing: not confirmed\n")
		b.WriteString("Username: not safely established\n")
		fmt.Fprintf(&b, "%s %s\n", evidencePasswordLabel("Password:"), evidenceValue(d.Value))
	} else if strings.EqualFold(d.MaterialFamily, "Credentials") && d.Value != "" {
		if d.Identity != "" {
			fmt.Fprintf(&b, "\n%s\n", evidenceSection("USERNAME + PASSWORD COMBINATION"))
			fmt.Fprintf(&b, "%s %s\n%s %s\n", evidenceLabel("Username:"), evidenceValue(qualifiedIdentity(d)), evidencePasswordLabel("Password:"), evidenceValue(d.Value))
		}
		fmt.Fprintf(&b, "Credential kind: %s\nOrigin type: %s\n", firstNonEmpty(credentialKind(d.MaterialType), "credential material"), firstNonEmpty(d.OriginType, "Unknown Origin Credential"))
	} else if strings.EqualFold(d.MaterialFamily, "Keys & Certificates") {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("KEY / CERTIFICATE MATERIAL"))
		fmt.Fprintf(&b, "Key or certificate type: %s\n", firstNonEmpty(keyType(d), "validated material"))
		if d.KeyFormat != "" {
			fmt.Fprintf(&b, "Format: %s\n", d.KeyFormat)
		}
		if d.KeyAlgorithm != "" {
			fmt.Fprintf(&b, "Algorithm: %s\n", d.KeyAlgorithm)
		}
		if d.KeyStatus != "" {
			fmt.Fprintf(&b, "Structural status: %s\n", d.KeyStatus)
		}
		if d.Encrypted {
			b.WriteString("Encryption: detected; decryption was not attempted.\n")
		}
		if d.Identity != "" {
			fmt.Fprintf(&b, "Associated identity: %s\n", qualifiedIdentity(d))
		}
		if d.Value != "" {
			b.WriteString("\nRecovered material\n")
			b.WriteString(d.Value)
			b.WriteByte('\n')
		}
	} else if d.Value != "" {
		if strings.Contains(strings.ToLower(d.PairingStatus), "encrypted") || strings.Contains(strings.ToLower(d.PairingStatus), "opaque") {
			fmt.Fprintf(&b, "\n%s\n", evidenceSection("ENCRYPTED / OPAQUE MATERIAL — REVIEW"))
			b.WriteString("Not confirmed plaintext; no decryption was attempted.\n")
		} else {
			fmt.Fprintf(&b, "\n%s\n", evidenceSection("RECOVERED MATERIAL"))
		}
		b.WriteString(evidenceValue(d.Value))
		b.WriteByte('\n')
	}
	if d.OriginType != "" && !strings.EqualFold(d.MaterialFamily, "Credentials") && d.MaterialType != "connection_string" && d.MaterialType != "dsn" {
		fmt.Fprintf(&b, "\nOrigin type: %s\n", d.OriginType)
	}
	if d.MaterialType == "connection_string" || d.MaterialType == "dsn" {
		fmt.Fprintf(&b, "\n%s\n%s\n", evidenceSection("ORIGINAL CONNECTION STRING"), evidenceValue(d.Value))
	}
	if len(d.ConnectionDetails) > 0 {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("CONNECTION STRING FIELDS"))
		for _, detail := range d.ConnectionDetails {
			fmt.Fprintf(&b, "%s: %s\n", detail.Label, detail.Value)
		}
	}
	if d.Identity != "" && d.Value == "" {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("IDENTITY / ACCOUNT REFERENCE — NO PASSWORD MATERIAL"))
	}
	fmt.Fprintf(&b, "\n%s\n%s\n", evidenceSection("IDENTITY"), firstNonEmpty(qualifiedIdentity(d), "not persisted"))
	if d.SourceContext != "" {
		fmt.Fprintf(&b, "Source context: %s\n", d.SourceContext)
	}
	fmt.Fprintf(&b, "Host: %s\nShare: %s\nSource: %s\n", firstNonEmpty(d.Host, "not persisted"), firstNonEmpty(d.Share, "not persisted"), firstNonEmpty(d.Path, "not persisted"))
	if len(d.Sources) > 0 || len(d.PersistedRefs) > 0 {
		fmt.Fprintf(&b, "\n%s\n", evidenceSection("SOURCE OBSERVATIONS"))
		for _, source := range d.Sources {
			fmt.Fprintf(&b, "%s\n", source)
		}
		for _, ref := range d.PersistedRefs {
			fmt.Fprintf(&b, "Persisted row: %s\n", ref)
		}
	}
	fmt.Fprintf(&b, "\n%s\nFinder category: %s\nFinder subcategory: %s\nFinder status: %s\n", evidenceSection("PRESENTATION CLASSIFICATION"), firstNonEmpty(d.MaterialFamily, "not assigned"), firstNonEmpty(d.Subcategory, "not assigned"), firstNonEmpty(d.Verification, "not assigned"))
	if d.Finding != nil {
		f := d.Finding
		fmt.Fprintf(&b, "Original scanner triage: %s\nOriginal scanner actionability: %t\nOriginal scanner confidence: %s\n", firstNonEmpty(f.TriageClass, "not assigned"), f.Actionable, firstNonEmpty(f.Confidence, "not assigned"))
		if f.MatchReason != "" {
			fmt.Fprintf(&b, "Scanner explanation: %s\n", f.MatchReason)
		}
	} else if d.PairingStatus != "" {
		fmt.Fprintf(&b, "Credential pairing status: %s\n", d.PairingStatus)
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
		fmt.Fprintf(&b, "\nORIGINAL SCANNER OBSERVATION — INTERPRETATION NOT ESTABLISHED\n------------------------------------------------------------\nRule: %s\nSeverity: %s\nCategory: %s\nRaw triage class: %s\nObservation ID: %s\n", firstNonEmpty(f.RuleName, f.RuleID), f.Severity, f.Category, firstNonEmpty(f.TriageClass, "not assigned"), firstNonEmpty(f.ObservationID, "not assigned"))
		if f.ArchivePath != "" || f.ArchiveMemberPath != "" {
			fmt.Fprintf(&b, "Archive container: %s\nArchive member: %s\n", firstNonEmpty(f.ArchivePath, "not persisted"), firstNonEmpty(f.ArchiveMemberPath, "not persisted"))
		}
		if f.LineNumber > 0 {
			fmt.Fprintf(&b, "Source line: %d\n", f.LineNumber)
		}
		if f.MatchedRuleIDs != nil {
			fmt.Fprintf(&b, "Rule IDs: %s\n", strings.Join(f.MatchedRuleIDs, ", "))
		}
	}
	return b.String()
}

func discoveryEvidence(d discovery) []string {
	if len(d.Evidence) > 0 {
		return d.Evidence
	}
	if d.Finding != nil {
		values := []string{d.Finding.MatchedText, d.Finding.Context, d.Finding.Snippet, d.Finding.Match}
		return uniqueNonEmpty(values)
	}
	if d.Value != "" {
		return []string{d.Value}
	}
	if d.RecoveredPassword != "" {
		return []string{d.RecoveredPassword}
	}
	return nil
}

func compactDiscoveries(categories []category) {
	for categoryIndex := range categories {
		for discoveryIndex := range categories[categoryIndex].Discoveries {
			d := &categories[categoryIndex].Discoveries[discoveryIndex]
			d.Value = ""
			d.RecoveredPassword = ""
			d.Evidence = nil
			d.ConnectionDetails = nil
			if d.Finding != nil {
				f := d.Finding
				f.Match = ""
				f.MatchedText = ""
				f.MatchedTextRedacted = ""
				f.Snippet = ""
				f.Context = ""
				f.ContextRedacted = ""
				f.ConfidenceReasons = nil
				f.MatchedRuleIDs = nil
				f.MatchedSignalTypes = nil
				d.Finding = nil
			}
		}
	}
}

func (m *model) hydrateDiscovery(d *discovery) {
	if m.provider == nil || len(d.PersistedRefs) == 0 {
		return
	}
	for _, ref := range d.PersistedRefs {
		item, ok := m.cachedEvidence(ref)
		if !ok {
			item = m.fetchEvidence(ref)
			if item.key == "" {
				continue
			}
			m.cacheEvidence(item)
		}
		switch {
		case item.finding != nil:
			finding := *item.finding
			d.Finding = &finding
			for _, value := range discoveryEvidenceFromFinding(finding) {
				d.Evidence = appendUnique(d.Evidence, value)
			}
		case item.candidate != nil:
			candidate := *item.candidate
			d.Value = candidate.Value
			d.RecoveredPassword = candidate.Value
			d.Evidence = appendUnique(d.Evidence, candidate.Value)
			d.ConnectionDetails = connectionDetails(candidate)
		case item.correlation != "":
			d.Value = item.correlation
			d.Evidence = appendUnique(d.Evidence, item.correlation)
		}
	}
}

func discoveryEvidenceFromFinding(f scanner.Finding) []string {
	return uniqueNonEmpty([]string{f.MatchedText, f.Context, f.Snippet, f.Match})
}

func (m *model) fetchEvidence(ref string) evidenceCacheItem {
	item := evidenceCacheItem{key: ref}
	scanID := m.scans[m.selectedScan].ID
	switch {
	case strings.HasPrefix(ref, "finding:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(ref, "finding:"), 10, 64)
		if err == nil {
			finding, err := m.provider.Finding(m.ctx, scanID, id)
			if err == nil {
				item.finding = &finding.Finding
			}
		}
	case strings.HasPrefix(ref, "correlation:"):
		key := strings.TrimPrefix(ref, "correlation:")
		correlation, err := m.provider.Correlation(m.ctx, scanID, key)
		if err == nil {
			item.correlation = correlation.Payload
		}
	default:
		credential, err := m.provider.Credential(m.ctx, scanID, ref)
		if err == nil {
			item.candidate = &credential.Candidate
		}
	}
	if item.finding == nil && item.candidate == nil && item.correlation == "" {
		item.key = ""
	}
	return item
}

func (m *model) cachedEvidence(key string) (evidenceCacheItem, bool) {
	item, ok := m.evidenceCache[key]
	return item, ok
}

func (m *model) cacheEvidence(item evidenceCacheItem) {
	if m.evidenceCache == nil {
		m.evidenceCache = make(map[string]evidenceCacheItem)
	}
	if _, exists := m.evidenceCache[item.key]; exists {
		return
	}
	item.size = len(item.correlation)
	if item.finding != nil {
		item.size += len(item.finding.MatchedText) + len(item.finding.Context) + len(item.finding.Snippet) + len(item.finding.Match)
	}
	if item.candidate != nil {
		item.size += len(item.candidate.Value) + len(item.candidate.Identity) + len(item.candidate.Path)
	}
	m.evidenceCache[item.key] = item
	m.evidenceOrder = append(m.evidenceOrder, item.key)
	m.evidenceBytes += item.size
	for len(m.evidenceOrder) > evidenceCacheLimit || m.evidenceBytes > evidenceCacheBytes {
		oldest := m.evidenceOrder[0]
		m.evidenceOrder = m.evidenceOrder[1:]
		m.evidenceBytes -= m.evidenceCache[oldest].size
		delete(m.evidenceCache, oldest)
	}
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func discoveryIsSecretBearing(d discovery) bool {
	if d.MaterialType == "correlation" || strings.EqualFold(d.Subcategory, "Secret References & Configuration Artifacts") {
		return false
	}
	if strings.EqualFold(d.MaterialFamily, "Credentials") || strings.EqualFold(d.MaterialFamily, "Keys & Certificates") {
		return len(discoveryEvidence(d)) > 0
	}
	if strings.EqualFold(d.MaterialFamily, "Connection & Database Secrets") {
		for _, detail := range d.ConnectionDetails {
			if strings.EqualFold(detail.Label, "Password") && detail.Value != "" {
				return true
			}
		}
	}
	if strings.EqualFold(d.MaterialFamily, "Application & Cloud Secrets") {
		return len(discoveryEvidence(d)) > 0
	}
	if d.Finding != nil {
		if strings.EqualFold(d.Finding.Category, "credentials") {
			return true
		}
		for _, tag := range d.Finding.Tags {
			lower := strings.ToLower(tag)
			if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") || strings.Contains(lower, "private-key") || strings.Contains(lower, "hash") || strings.Contains(lower, "password") {
				return true
			}
		}
	}
	return false
}

func correlationTitle(key string, record credentialanalysis.Correlation, parsed bool) string {
	if !parsed {
		return "Cross-file relationship — " + key
	}
	typ := firstNonEmpty(record.Type, "correlation")
	sources := uniqueCorrelationSourceCount(record.Sources)
	return fmt.Sprintf("%s — %d source observations", correlationLabel(typ), sources)
}

func correlationLabel(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "same_identity_value":
		return "Same identity/value relationship"
	case "same_identity_type":
		return "Same identity/type relationship"
	default:
		return "Cross-file relationship (" + firstNonEmpty(typ, "unknown type") + ")"
	}
}

func correlationSourceLabel(source credentialanalysis.CorrelationSource) string {
	path := source.Path
	if source.Container != "" && !strings.HasPrefix(path, source.Container+"!") {
		path = source.Container + "!" + path
	}
	if source.Host != "" && source.Share != "" {
		return fmt.Sprintf("\\\\%s\\%s\\%s", source.Host, source.Share, strings.TrimPrefix(path, "\\"))
	}
	if source.Share != "" {
		return fmt.Sprintf("%s\\%s", source.Share, strings.TrimPrefix(path, "\\"))
	}
	return path
}

func uniqueCorrelationSourceCount(sources []credentialanalysis.CorrelationSource) int {
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		label := correlationSourceLabel(source)
		if label == "" {
			label = "(source path unavailable)"
		}
		seen[label] = struct{}{}
	}
	return len(seen)
}

func correlationEvidenceText(d discovery) string {
	var b strings.Builder
	sources := d.CorrelationSources
	count := uniqueCorrelationSourceCount(sources)
	fmt.Fprintf(&b, "%s\n%s\nSource-backed relationship record; original secret values remain in the related source observations below.\n\nRelationship: %s\nMaterial type: %s\nVerification: %s\nConfidence: %s\nRelated source observations: %d\n", evidenceSection("OBSERVED EVIDENCE"), d.Title, correlationLabel(d.CorrelationType), firstNonEmpty(d.CorrelationType, "unknown"), firstNonEmpty(d.Verification, "persisted correlation"), firstNonEmpty(d.Confidence, "contextual"), count)
	if d.CorrelationIdentity != "" {
		fmt.Fprintf(&b, "Identity reference: %s\n", d.CorrelationIdentity)
	}
	if d.CorrelationDomain != "" {
		fmt.Fprintf(&b, "Domain: %s\n", d.CorrelationDomain)
	}
	if d.CorrelationConfidenceRationale != "" {
		fmt.Fprintf(&b, "Rationale: %s\n", d.CorrelationConfidenceRationale)
	}
	fmt.Fprintf(&b, "\n%s\n", evidenceSection("RELATED SOURCES"))
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		label := correlationSourceLabel(source)
		if label == "" {
			label = "(source path unavailable)"
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		fmt.Fprintf(&b, "%d. %s\n", len(seen), label)
	}
	if len(seen) == 0 {
		b.WriteString("Source provenance unavailable in this correlation record.\n")
	}
	if d.CorrelationConfidenceRationale != "" {
		fmt.Fprintf(&b, "\n%s\n%s\n", evidenceSection("RELATIONSHIP EVIDENCE"), d.CorrelationConfidenceRationale)
	}
	fmt.Fprintf(&b, "\n%s\nCorrelation key: %s\n", evidenceSection("RAW RECORD"), firstNonEmpty(d.CorrelationKey, "not persisted"))
	if d.CorrelationParsed {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, []byte(d.Value), "", "  "); err == nil {
			b.WriteString(pretty.String())
		} else {
			b.WriteString(d.Value)
		}
	} else {
		b.WriteString("Raw record is not valid JSON; displaying the persisted payload exactly.\n")
		b.WriteString(d.Value)
	}
	b.WriteByte('\n')
	return b.String()
}

func wrapDetails(value string, width int) string {
	return ansi.Wrap(value, max(1, width), " \t/:!?=,;|\\")
}

func evidenceSection(title string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#60A5FA")).Render(title)
}

func evidenceSectionForDiscovery(title string, d discovery) string {
	if discoveryIsSecretBearing(d) {
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FB923C")).Render(title)
	}
	return evidenceSection(title)
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

func evidenceValueForDiscovery(value string, d discovery) string {
	if discoveryIsSecretBearing(d) {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#FB923C")).Render(value)
	}
	return evidenceValue(value)
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
	case "PEM Keys":
		if d.KeyAlgorithm != "" {
			return d.KeyAlgorithm + " private key"
		}
		return "PEM private key"
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
		listRows = len(m.categoryItems())
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
	displayID := scan.DisplayID
	if displayID == "" {
		displayID = scan.ID
	}
	header := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).Render("SNABLR // FINDINGS") + "  " + displayID + "  " + displayScanStatus(scan.Status)
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
		footer := "PgUp/PgDn scroll  ←/Esc back  Ctrl-C quit"
		return joinFinderSections(header, crumb, panel, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(footer+"  "+m.status))
	}
	left := style.Render(panelHeader(leftTitle, m.focus == 0, m.list.Width, section) + "\n" + leftContent)
	preview := style.Render(panelHeader(rightTitle, m.focus == 1, m.preview.Width, section) + "\n" + rightContent)
	footer := "↑/↓ j/k move  Enter/→ open  ←/Esc back  PgUp/PgDn scroll  Ctrl-C quit"
	if m.screen == screenCategories || m.selectingScan {
		footer = "↑/↓ j/k move  Enter/→ select  Ctrl-C quit"
	}
	if m.screen == screenDiscoveries {
		footer = "↑/↓ j/k move  / filter  Enter/→ open  ←/Esc back  PgUp/PgDn scroll  Ctrl-C quit"
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
		displayID := scan.DisplayID
		if displayID == "" {
			displayID = scan.ID
		}
		lines = append(lines, marker+displayID+"  "+displayScanStatus(scan.Status)+"  "+scan.Targets+fmt.Sprintf("  %d findings", scan.FindingCount))
	}
	return strings.Join(lines, "\n")
}

func displayScanStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed_with_skips":
		return "completed with skips"
	case "timed_out":
		return "timed out"
	default:
		return status
	}
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
	discoveries := subcategoryDiscoveries(item, subs[selected])
	return fmt.Sprintf("%s\n\nLogical discoveries: %d\nPersisted rows represented: %d", subs[selected], len(discoveries), persistedRefCount(discoveries))
}

func persistedRefCount(items []discovery) int {
	count := 0
	for _, item := range items {
		count += len(item.PersistedRefs)
	}
	return count
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

func (m *model) categoryItems() []category {
	if len(m.allMaterial.Discoveries) == 0 {
		return m.categories
	}
	items := make([]category, 0, len(m.categories)+1)
	items = append(items, m.allMaterial)
	return append(items, m.categories...)
}

func (m *model) isAllMaterial() bool {
	items := m.categoryItems()
	return m.screen != screenCategories && m.selected >= 0 && m.selected < len(items) && items[m.selected].Name == "All Persisted Material"
}

func buildAllPersistedMaterial(categories []category) category {
	all := category{Name: "All Persisted Material", Description: "Every persisted credential-material discovery, grouped by evidence status"}
	for _, group := range categories {
		for _, original := range group.Discoveries {
			if len(original.PersistedRefs) == 0 {
				continue
			}
			item := original
			item.Subcategory = persistedMaterialStatus(original)
			all.Discoveries = append(all.Discoveries, item)
		}
	}
	return all
}

func persistedMaterialStatus(item discovery) string {
	status := strings.TrimSpace(item.PairingStatus)
	lowerStatus := strings.ToLower(status)
	reason := strings.ToLower(item.Reason)
	if strings.Contains(reason, "suppress") || strings.Contains(reason, "placeholder") || strings.Contains(reason, "invalid") {
		return "Suppressed / Invalid (Audit Only)"
	}
	switch {
	case strings.EqualFold(status, "Confirmed pair"):
		return "Confirmed Username + Password"
	case strings.EqualFold(status, "Confirmed pair (Finder-derived)"):
		return "Finder-Derived Pair"
	case strings.Contains(lowerStatus, "encrypted"), strings.Contains(lowerStatus, "opaque"):
		return "Encrypted / Opaque"
	case strings.TrimSpace(item.Value) == "" && strings.TrimSpace(item.Identity) != "":
		return "Identity / Account Reference"
	case strings.TrimSpace(item.Value) == "":
		return "Supporting / Reference Only"
	case strings.TrimSpace(item.Identity) == "":
		return "Password Only"
	case strings.Contains(lowerStatus, "uncertain"), strings.EqualFold(strings.TrimSpace(item.OriginalVerification), "review"):
		return "Uncertain / Review"
	default:
		return "Other Persisted Material"
	}
}

func filterDiscoveries(items []discovery, query string) []discovery {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	result := make([]discovery, 0, len(items))
	for _, item := range items {
		fields := []string{item.Title, item.Subcategory, item.MaterialType, item.Identity, item.Domain, item.Value, item.Host, item.Share, item.Path, item.SourceContext, item.OriginType, item.PairingStatus, item.Reason}
		if item.Finding != nil {
			fields = append(fields, item.Finding.RuleID, item.Finding.RuleName, item.Finding.Category, item.Finding.TriageClass, item.Finding.SignalType, item.Finding.Match, item.Finding.MatchedText, item.Finding.Snippet, item.Finding.Context, item.Finding.ArchivePath, item.Finding.ArchiveMemberPath, item.Finding.ObservationID)
		}
		fields = append(fields, item.Sources...)
		matched := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), query) {
				matched = true
				break
			}
		}
		if matched {
			result = append(result, item)
		}
	}
	return result
}

func (m *model) handleFilterKey(msg tea.KeyMsg) {
	previous := ""
	if len(m.discoveries) > 0 && m.selectedDisc >= 0 && m.selectedDisc < len(m.discoveries) {
		previous = discoveryReference(m.discoveries[m.selectedDisc])
	}
	switch msg.String() {
	case "esc":
		m.filterMode = false
	case "enter":
		m.filterMode = false
	case "backspace":
		if runes := []rune(m.filter); len(runes) > 0 {
			m.filter = string(runes[:len(runes)-1])
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.filter += string(msg.Runes)
		}
	}
	m.status = "Filter: " + m.filter
	m.refresh()
	if previous != "" {
		for index, item := range m.discoveries {
			if discoveryReference(item) == previous {
				m.selectedDisc = index
				m.refresh()
				break
			}
		}
	}
}

func discoveryReference(item discovery) string {
	if len(item.PersistedRefs) > 0 {
		return item.PersistedRefs[0]
	}
	return item.MaterialType + "\x00" + item.Identity + "\x00" + item.Path + "\x00" + item.Title
}

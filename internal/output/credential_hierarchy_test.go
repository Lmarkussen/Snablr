package output

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
)

// Every identity, host, share, path and value in this file is independently
// invented synthetic data. None of it is derived from customer, lab or live
// scan material.

func renderCredentialHierarchyReport(t *testing.T, candidates []credentialanalysis.Candidate) string {
	t.Helper()
	var out bytes.Buffer
	writer, err := NewHTMLWriter(&out, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(syntheticCredentialFinding()); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if err := writer.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	return out.String()
}

func sectionByID(html, id string) string {
	start := strings.Index(html, `id="`+id+`"`)
	if start < 0 {
		return ""
	}
	end := strings.Index(html[start:], "</section>")
	if end < 0 {
		return html[start:]
	}
	return html[start : start+end]
}

var credentialRowPattern = regexp.MustCompile(`(?s)<tr class="credential-row ([a-z-]+)">(.*?)</tr>`)

func credentialTableRows(t *testing.T, section, class string) [][]string {
	t.Helper()
	var rows [][]string
	for _, match := range credentialRowPattern.FindAllStringSubmatch(section, -1) {
		if match[1] != class {
			continue
		}
		raw := regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`).FindAllStringSubmatch(match[2], -1)
		cells := make([]string, 0, len(raw))
		for _, cell := range raw {
			cells = append(cells, strings.TrimSpace(stripHTMLTags(cell[1])))
		}
		rows = append(rows, cells)
	}
	return rows
}

func stripHTMLTags(value string) string {
	return regexp.MustCompile(`<[^>]+>`).ReplaceAllString(value, " ")
}

func actionableCreditseeds() []credentialanalysis.Candidate {
	return []credentialanalysis.Candidate{
		{
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "password",
			Identity:       "synthetic-user",
			Value:          "SyntheticPair482!",
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "configs/synthetic-pair.ini",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "Administrator",
			Value:           "Summer2026.",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/synthetic-admin.ini",
			ValidationBasis: "structured configuration section",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "connection_string",
			Value:           "Server=db.synthetic.test;User ID=svc_synthetic;Password=SyntheticDB482!;",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/synthetic-db.config",
			ValidationBasis: "validated_database_connection_string",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "private_key",
			Value:           "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "keys/synthetic-id_ed25519",
			ValidationBasis: "parsed_private_key",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "nt_hash",
			Identity:        "synthetic-admin",
			Domain:          "SYNTHETIC",
			Value:           "00112233445566778899aabbccddeeff",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "Windows/NTDS/ntds.dit",
			Source:          "Windows/NTDS/ntds.dit",
			ValidationBasis: "cryptographic_ntds_recovery",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "archive-user",
			Value:           "SyntheticArchive482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "packages/configs.zip!app/settings.ini",
			Container:       "packages/configs.zip",
			ValidationBasis: "structured configuration section",
		},
	}
}

func supportingCorrelationCandidates(count int) []credentialanalysis.Candidate {
	candidates := []credentialanalysis.Candidate{
		{
			// Identity-only correlation: a credential-related record type with no
			// secret value at all.
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "application/deployment credential indicator",
			Identity:       "synthetic-service",
			Material:       credentialanalysis.MaterialCorrelation,
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "deploy/synthetic-locations.ini",
		},
		{
			// Configuration correlation without a secret value.
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "configuration credential correlation",
			Identity:       "synthetic-config-account",
			Material:       credentialanalysis.MaterialCorrelation,
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "configs/synthetic-correlation.ini",
		},
		{
			// Path-only credential store: presence, not a recovered secret.
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "credential_store_presence",
			Material:       credentialanalysis.MaterialCorrelation,
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "Users/synthetic/AppData/Local/Synthetic/credential-store",
		},
	}
	// One correlation observed in many locations must stay a single row.
	for index := 0; index < count; index++ {
		candidates = append(candidates, credentialanalysis.Candidate{
			Verification:   credentialanalysis.Confirmed,
			CredentialType: "application/deployment credential indicator",
			Identity:       "synthetic-service",
			Material:       credentialanalysis.MaterialCorrelation,
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "deploy/locations/synthetic-" + strconv.Itoa(index) + ".ini",
		})
	}
	return candidates
}

// TestCredentialHierarchySplitsActionableFromSupporting is the synthetic matrix
// for credential placement: only records with a real secret type stay in the
// top table, and credential-related records without a secret move below the
// findings hierarchy.
func TestCredentialHierarchySplitsActionableFromSupporting(t *testing.T) {
	t.Parallel()

	candidates := append(actionableCreditseeds(), supportingCorrelationCandidates(39)...)
	html := renderCredentialHierarchyReport(t, candidates)

	top := sectionByID(html, "credential-analysis")
	if top == "" {
		t.Fatal("credential section is missing")
	}
	actionable := credentialTableRows(t, top, "confirmed-row")
	if len(actionable) != len(actionableCreditseeds()) {
		t.Fatalf("actionable rows = %d, want %d", len(actionable), len(actionableCreditseeds()))
	}
	for _, row := range actionable {
		if row[1] == "" || !credentialanalysis.IsSecretMaterialType(row[1]) {
			t.Fatalf("non-secret row reached the actionable table: %v", row)
		}
	}
	for _, candidate := range actionableCreditseeds() {
		if !strings.Contains(top, candidate.Value) {
			t.Fatalf("confirmed value %q is missing from the HTML credential table", candidate.Value)
		}
	}
	for _, unwanted := range []string{
		"application/deployment credential indicator",
		"configuration credential correlation",
		"credential_store_presence",
	} {
		if strings.Contains(top, unwanted) {
			t.Fatalf("supporting correlation %q is rendered in the top credential section", unwanted)
		}
	}

	supporting := sectionByID(html, "credential-correlations")
	if supporting == "" {
		t.Fatal("supporting credential correlation section is missing")
	}
	supportingRows := credentialTableRows(t, supporting, "supporting-correlation-row")
	if len(supportingRows) != 3 {
		t.Fatalf("supporting rows = %d, want 3 (the 39 duplicate locations aggregate into one)", len(supportingRows))
	}
	if !strings.Contains(supporting, "Supporting Credential Correlations") {
		t.Fatal("supporting section is not labelled")
	}
	if !strings.Contains(supporting, `<details class="table-card group" id="credential-correlation-rows">`) {
		t.Fatal("supporting section is not rendered as a collapsed block")
	}

	findingsAt := strings.Index(html, `id="findings"`)
	supportingAt := strings.Index(html, `id="credential-correlations"`)
	if findingsAt < 0 || supportingAt < 0 || supportingAt < findingsAt {
		t.Fatalf("supporting correlations are not placed below the findings section (findings=%d supporting=%d)", findingsAt, supportingAt)
	}
}

// TestCredentialProvenanceIsCollapsed covers the observation-count and
// provenance requirements: one primary location inline, the remainder inside a
// collapsed block, and a bounded list for very wide observations.
func TestCredentialProvenanceIsCollapsed(t *testing.T) {
	t.Parallel()

	correlation := supportingCorrelationCandidates(0)[0]
	var candidates []credentialanalysis.Candidate
	for index := 0; index < 40; index++ {
		observed := correlation
		observed.Path = "deploy/locations/synthetic-" + strconv.Itoa(index) + ".ini"
		candidates = append(candidates, observed)
	}

	html := renderCredentialHierarchyReport(t, candidates)
	supporting := sectionByID(html, "credential-correlations")
	rows := credentialTableRows(t, supporting, "supporting-correlation-row")
	if len(rows) != 1 {
		t.Fatalf("aggregated rows = %d, want 1", len(rows))
	}
	if rows[0][5] != "40" {
		t.Fatalf("observation count = %q, want 40", rows[0][5])
	}
	if !strings.Contains(rows[0][4], "Also found in 39 additional locations (40 observations)") {
		t.Fatalf("collapsed provenance summary missing: %q", rows[0][4])
	}
	if count := strings.Count(supporting, "<li>"); count != 39 {
		t.Fatalf("collapsed locations = %d, want 39", count)
	}
	primary := `\\synthetic-host.test\SyntheticShare\deploy\locations\synthetic-0.ini`
	if !strings.HasPrefix(strings.TrimSpace(rows[0][4]), primary) {
		t.Fatalf("primary source is not visible first in the cell: %q", rows[0][4])
	}

	var wideCandidates []credentialanalysis.Candidate
	for index := 0; index < 120; index++ {
		observed := correlation
		observed.Path = "deploy/locations/synthetic-" + strconv.Itoa(index) + ".ini"
		wideCandidates = append(wideCandidates, observed)
	}
	wide := renderCredentialHierarchyReport(t, wideCandidates)
	wideSection := sectionByID(wide, "credential-correlations")
	if count := strings.Count(wideSection, "<li>"); count != maxCredentialExtraLocations {
		t.Fatalf("wide provenance rendered %d locations, want the bounded %d", count, maxCredentialExtraLocations)
	}
	if !strings.Contains(wide, "Showing the first 40 of 119 additional locations") {
		t.Fatal("bounded provenance block does not explain how many locations were withheld")
	}
}

// TestCredentialHierarchyKeepsDuplicateRealCredentials proves the hierarchy
// change does not drop or split a real credential observed in several places.
func TestCredentialHierarchyKeepsDuplicateRealCredentials(t *testing.T) {
	t.Parallel()

	candidates := []credentialanalysis.Candidate{
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "svc_duplicate",
			Value:           "SyntheticDuplicate482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/one/synthetic-app.ini",
			ValidationBasis: "structured configuration section",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "svc_duplicate",
			Value:           "SyntheticDuplicate482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/two/synthetic-app.ini",
			ValidationBasis: "structured configuration section",
		},
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "svc_duplicate",
			Value:           "SyntheticDuplicate482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/three/synthetic-app.ini",
			ValidationBasis: "structured configuration section",
		},
	}
	html := renderCredentialHierarchyReport(t, candidates)
	actionable := credentialTableRows(t, sectionByID(html, "credential-analysis"), "confirmed-row")
	if len(actionable) != 1 {
		t.Fatalf("duplicate real credential rendered %d rows, want 1", len(actionable))
	}
	if actionable[0][6] != "3" {
		t.Fatalf("observation count = %q, want 3", actionable[0][6])
	}
	if !strings.Contains(sectionByID(html, "credential-analysis"), "Also found in 2 additional locations") {
		t.Fatal("duplicate real credential lost its additional locations")
	}
}

// TestCredentialSummaryCountsExcludeCorrelations covers the counter rules.
func TestCredentialSummaryCountsExcludeCorrelations(t *testing.T) {
	t.Parallel()

	candidates := append(actionableCreditseeds(), supportingCorrelationCandidates(0)...)
	html := renderCredentialHierarchyReport(t, candidates)
	cards := regexp.MustCompile(`(?s)card-label">(.*?)</span>\s*<span class="card-value">(\d+)</span>`).FindAllStringSubmatch(sectionByID(html, "credential-analysis"), -1)
	counts := map[string]string{}
	for _, card := range cards {
		counts[strings.TrimSpace(card[1])] = card[2]
	}
	if counts["Confirmed Credentials"] != strconv.Itoa(len(actionableCreditseeds())) {
		t.Fatalf("confirmed credential count = %q, want %d", counts["Confirmed Credentials"], len(actionableCreditseeds()))
	}
	if counts["Supporting Credential Correlations"] != "3" {
		t.Fatalf("supporting correlation count = %q, want 3", counts["Supporting Credential Correlations"])
	}
	if counts["High-Value Recovered Secrets"] != "2" {
		t.Fatalf("recovered secret count = %q, want 2", counts["High-Value Recovered Secrets"])
	}
}

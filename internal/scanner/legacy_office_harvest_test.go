package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/legacyfixture"
	"snablr/internal/officefixture"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func evaluateLegacyFixture(t *testing.T, manager *rules.Manager, name string, content []byte) (Evaluation, []credentialanalysis.Candidate) {
	t.Helper()
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		Host: "fs01", Share: "share", FilePath: "PasswordList/" + name,
		Name: name, Extension: filepath.Ext(name), Size: int64(len(content)),
	}, content)
	return evaluation, collector.candidates
}

// TestLegacyOfficeCredentialOracle is the ground-truth oracle for legacy Office:
// visible text from real Word 97-2003 / Excel 97-2003 structures reaches the
// shared credential semantics, and documentation/legacy metadata does not.
func TestLegacyOfficeCredentialOracle(t *testing.T) {
	manager := loadOfficeRules(t)

	type want struct {
		identity string
		domain   string
		value    string
	}
	positives := []struct {
		name    string
		content []byte
		want    []want
	}{
		{
			name:    "Norwegian pair",
			content: legacyfixture.Word("Brukernavn: svc_legacy\rDomene: KUNDE\rPassord: Synthetic-Legacy-123!\r"),
			want:    []want{{identity: "svc_legacy", domain: "KUNDE", value: "Synthetic-Legacy-123!"}},
		},
		{
			name:    "English pair",
			content: legacyfixture.Word("Username: legacy_user\rDomain: KUNDE\rPassword: English-Legacy-456!\r"),
			want:    []want{{identity: "legacy_user", domain: "KUNDE", value: "English-Legacy-456!"}},
		},
		{
			name:    "password list style",
			content: legacyfixture.WordCP1252("Passord: CP1252-Legacy-789! ÆØÅ\r"),
			want:    []want{{value: "CP1252-Legacy-789! ÆØÅ"}},
		},
		{
			name:    "unicode Norwegian",
			content: legacyfixture.Word("Brukernavn: svc_uni\rPassord: Unicode-Legacy-ÆØÅ-321!\r"),
			want:    []want{{identity: "svc_uni", value: "Unicode-Legacy-ÆØÅ-321!"}},
		},
		{
			name: "doc table rows",
			content: legacyfixture.WordTable(
				[]string{"USERNAME", "Passord"},
				[]string{"Bob", "Synthetic-Bob-123!"},
				[]string{"Jane", "Synthetic-Jane-456!"},
			),
			want: []want{
				{identity: "Bob", value: "Synthetic-Bob-123!"},
				{identity: "Jane", value: "Synthetic-Jane-456!"},
			},
		},
		{
			name: "xls Norwegian table",
			content: legacyfixture.Workbook([][]string{
				{"Brukernavn", "Passord", "Domene"},
				{"user1", "Legacy-One-123!", "KUNDE"},
				{"user2", "Legacy-Two-456!", "KUNDE"},
			}),
			want: []want{
				{identity: "user1", domain: "KUNDE", value: "Legacy-One-123!"},
				{identity: "user2", domain: "KUNDE", value: "Legacy-Two-456!"},
			},
		},
		{
			name: "xls reversed columns",
			content: legacyfixture.Workbook([][]string{
				{"Passord", "Brukernavn"},
				{"First-123!", "bruker1"},
				{"Second-456!", "bruker2"},
			}),
			want: []want{
				{identity: "bruker1", value: "First-123!"},
				{identity: "bruker2", value: "Second-456!"},
			},
		},
	}

	missed := 0
	for _, test := range positives {
		_, candidates := evaluateLegacyFixture(t, manager, test.name, test.content)
		for _, expected := range test.want {
			if !hasOfficeCandidate(candidates, expected.value, expected.identity, expected.domain) {
				missed++
				t.Errorf("%s: legacy credential %q (identity %q) was not surfaced: %#v", test.name, expected.value, expected.identity, candidates)
			}
		}
		// Cross-row safety for tabular legacy documents.
		for _, candidate := range candidates {
			for _, expected := range test.want {
				if candidate.Value == expected.value && candidate.Identity != "" && expected.identity != "" && candidate.Identity != expected.identity {
					t.Errorf("%s: cross-row fabricated pair %q -> %q", test.name, candidate.Identity, candidate.Value)
				}
			}
		}
	}
	if missed != 0 {
		t.Fatalf("legacy positives missed: %d", missed)
	}

	negatives := []struct {
		name    string
		content []byte
	}{
		{"legacy doc policy", legacyfixture.Word("PassordPolicy: Kompleksitet\rPassordLengde: 14\rPassordHistorikk: 24\r")},
		{"legacy doc documentation", legacyfixture.Word("Passordrutiner\rBruk sterke passord og bytt dem ofte.\r")},
		{"legacy xls policy", legacyfixture.Workbook([][]string{{"Setting", "Value"}, {"PassordLengde", "14"}, {"PassordHistorikk", "24"}})},
		{"encrypted legacy doc", legacyfixture.WordEncrypted()},
		{"encrypted legacy xls", legacyfixture.WorkbookEncrypted()},
	}
	for _, test := range negatives {
		_, candidates := evaluateLegacyFixture(t, manager, test.name, test.content)
		if len(candidates) != 0 {
			t.Errorf("%s: legacy negative produced credential candidates: %#v", test.name, candidates)
		}
	}
}

// TestLegacyOfficeFilenameDiscovery covers filename/path discovery for the live
// legacy shape even when content cannot be inspected.
func TestLegacyOfficeFilenameDiscovery(t *testing.T) {
	manager := loadOfficeRules(t)
	evaluation, _ := evaluateLegacyFixture(t, manager, "passordliste redacted.doc", legacyfixture.WordEncrypted())
	if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") &&
		!hasRuleID(evaluation.Findings, "filename.credentials_and_secrets_keywords") {
		t.Fatalf("legacy credential-list filename was not discovered: %v", ruleIDs(evaluation.Findings))
	}
}

// TestLegacyOfficeInsideArchiveAndWIM proves nested legacy documents use the
// same parser and keep container provenance.
func TestLegacyOfficeInsideArchiveAndWIM(t *testing.T) {
	manager := loadOfficeRules(t)
	doc := legacyfixture.Word("Brukernavn: svc_zip\rDomene: KUNDE\rPassord: Zip-Legacy-123!\r")

	// ZIP -> .doc
	archive := officefixture.ZIPBytes(map[string]string{"PasswordList/synthetic.doc": string(doc)})
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	engine.EvaluateContext(context.Background(), FileMetadata{
		Host: "fs01", Share: "share", FilePath: "backup.zip", Name: "backup.zip", Extension: ".zip", Size: int64(len(archive)),
	}, archive)
	if !hasOfficeCandidate(collector.candidates, "Zip-Legacy-123!", "svc_zip", "KUNDE") {
		t.Fatalf("legacy document inside a ZIP was not harvested: %#v", collector.candidates)
	}
	for _, candidate := range collector.candidates {
		if candidate.Path != "" && !containsAll(candidate.Path, "backup.zip", "synthetic.doc") {
			t.Errorf("nested legacy provenance lost: %#v", candidate)
		}
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}

// TestLegacyOfficeContentFindingsAreActionable covers extension parity: legacy
// .doc/.xls content that reaches the shared harvester must also produce the
// actionable content finding the modern formats produce.
func TestLegacyOfficeContentFindingsAreActionable(t *testing.T) {
	manager := loadOfficeRules(t)
	cases := []struct {
		name    string
		content []byte
		value   string
	}{
		{
			name:    "synthetic.doc",
			content: legacyfixture.Word("Brukernavn: svc_backup\rDomene: KUNDE\rPassord: Legacy-Word-123!\r"),
			value:   "Legacy-Word-123!",
		},
		{
			name: "synthetic.xls",
			content: legacyfixture.Workbook([][]string{
				{"Brukernavn", "Passord"},
				{"user1", "Legacy-XLS-123!"},
			}),
			value: "Legacy-XLS-123!",
		},
	}
	for _, test := range cases {
		evaluation, candidates := evaluateLegacyFixture(t, manager, test.name, test.content)
		if !hasOfficeCandidate(candidates, test.value, "", "") {
			t.Errorf("%s: credential %q was not surfaced", test.name, test.value)
		}
		if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
			t.Fatalf("%s: expected an actionable content finding, got %v", test.name, ruleIDs(evaluation.Findings))
		}
		actionable := false
		for _, finding := range evaluation.Findings {
			if finding.RuleID == "content.password_assignment_indicators" {
				if finding.Severity != "high" {
					t.Errorf("%s: severity = %q, want high", test.name, finding.Severity)
				}
				actionable = finding.Actionable
			}
		}
		if !actionable {
			t.Errorf("%s: content finding was not actionable", test.name)
		}
	}
}

// TestLegacyOfficePolicyDocumentsStayNonCredential keeps the negatives clean now
// that .doc/.xls participate in content rules.
func TestLegacyOfficePolicyDocumentsStayNonCredential(t *testing.T) {
	manager := loadOfficeRules(t)
	for _, content := range [][]byte{
		legacyfixture.Word("PassordPolicy: Kompleksitet\rPassordLengde: 14\rPassordHistorikk: 24\r"),
		legacyfixture.Workbook([][]string{{"Setting", "Value"}, {"PassordLengde", "14"}}),
	} {
		_, candidates := evaluateLegacyFixture(t, manager, "policy", content)
		if len(candidates) != 0 {
			t.Fatalf("legacy policy document produced credential candidates: %#v", candidates)
		}
	}
}

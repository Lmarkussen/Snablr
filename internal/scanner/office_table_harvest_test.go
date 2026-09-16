package scanner

import (
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
)

// TestHeaderRowCredentialTableOracle is the regression for the live failure
// class: DOCX password lists stored as a table whose first row defines the
// column semantics and whose following rows are independent credential records.
//
// Expectations are exact: expected credentials, their identity/domain pairing,
// and zero cross-row fabrication.
func TestHeaderRowCredentialTableOracle(t *testing.T) {
	manager := loadOfficeRules(t)

	type expected struct {
		identity string
		domain   string
		value    string
	}
	cases := []struct {
		fixture string
		want    []expected
	}{
		{"table-a-mixed.docx", []expected{
			{"Bob", "", "Synthetic-Bob-123!"},
			{"Jane", "", "Synthetic-Jane-456!"},
		}},
		{"table-b-norwegian.docx", []expected{
			{"ola", "", "Norsk-Ola-123!"},
			{"kari", "", "Norsk-Kari-456!"},
		}},
		{"table-c-english.docx", []expected{
			{"alice", "", "English-Alice-123!"},
			{"bob", "", "English-Bob-456!"},
		}},
		{"table-d-domain.docx", []expected{
			{"svc_backup", "KUNDE", "Backup-123!"},
			{"svc_sql", "KUNDE", "SQL-456!"},
		}},
		{"table-e-reversed.docx", []expected{
			{"bruker1", "", "First-123!"},
			{"bruker2", "", "Second-456!"},
		}},
		{"table-f-extra-columns.docx", []expected{
			{"svc_one", "", "One-123!"},
			{"svc_two", "", "Two-456!"},
		}},
		{"table-g-blank-password.docx", []expected{
			{"user1", "", "One-123!"},
			{"user3", "", "Three-789!"},
		}},
		{"table-i-split-runs.docx", []expected{
			{"svc_run", "", "Run-123!"},
		}},
		{"table-i2-multi-paragraph-header.docx", []expected{
			{"svc_multi", "", "Multi-123!"},
		}},
		{"table-j-multiple-tables.docx", []expected{
			{"svc1", "", "Secret1!"},
		}},
		{"table-p7-title-then-header.docx", []expected{
			{"svc1", "", "Secret1!"},
		}},
		{"table-p8-repeated-header.docx", []expected{
			{"user1", "", "One-123!"},
			{"user2", "", "Two-456!"},
			{"user3", "", "Three-789!"},
		}},
		{"table-p9-merged-title.docx", []expected{
			{"user1", "", "One-123!"},
		}},
		{"PasswordList-table.docx", []expected{
			{"Bob", "", "Synthetic-Bob-123!"},
			{"Jane", "", "Synthetic-Jane-456!"},
		}},
		{"nested-password-list.zip", []expected{
			{"Bob", "", "Synthetic-Bob-123!"},
			{"Jane", "", "Synthetic-Jane-456!"},
		}},
		{"table-credentials.xlsx", []expected{
			{"Bob", "", "Synthetic-Bob-123!"},
			{"Jane", "", "Synthetic-Jane-456!"},
		}},
	}

	for _, test := range cases {
		evaluation, candidates := evaluateOfficeFixture(t, manager, test.fixture, true)
		surfaced := map[string]credentialanalysis.Candidate{}
		for _, candidate := range candidates {
			surfaced[candidate.Value] = candidate
		}
		if len(surfaced) != len(test.want) {
			t.Errorf("%s: surfaced %d credentials, want %d (%#v)", test.fixture, len(surfaced), len(test.want), candidates)
		}
		for _, item := range test.want {
			candidate, ok := surfaced[item.value]
			if !ok {
				t.Errorf("%s: credential %q for identity %q was not surfaced", test.fixture, item.value, item.identity)
				continue
			}
			if candidate.Verification != credentialanalysis.Confirmed {
				t.Errorf("%s: %q verification = %q, want confirmed", test.fixture, item.value, candidate.Verification)
			}
			if candidate.Identity != item.identity {
				t.Errorf("%s: %q identity = %q, want %q (cross-row pairing?)", test.fixture, item.value, candidate.Identity, item.identity)
			}
			if candidate.Domain != item.domain {
				t.Errorf("%s: %q domain = %q, want %q", test.fixture, item.value, candidate.Domain, item.domain)
			}
		}
		// Explicit cross-row guard: no row's password may be attributed to another
		// row's identity.
		for _, candidate := range candidates {
			for _, item := range test.want {
				if candidate.Value == item.value && candidate.Identity != "" && candidate.Identity != item.identity {
					t.Errorf("%s: cross-row fabricated pair %q -> %q", test.fixture, candidate.Identity, candidate.Value)
				}
			}
		}
		if len(evaluation.Findings) == 0 {
			t.Errorf("%s: no findings at all for a credential-bearing table", test.fixture)
		}
		if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
			t.Errorf("%s: no actionable content finding for the credential table", test.fixture)
		}
	}
}

// TestHeaderRowCredentialTableNegatives keeps policy, description, and
// requirement tables out of the credential model.
func TestHeaderRowCredentialTableNegatives(t *testing.T) {
	manager := loadOfficeRules(t)
	for _, fixture := range []string{
		"table-n1-policy.docx",
		"table-n2-description.docx",
		"table-n3-requirement.docx",
		"table-n4-username-description.docx",
		"table-n5-password-comment.docx",
	} {
		_, candidates := evaluateOfficeFixture(t, manager, fixture, true)
		if len(candidates) != 0 {
			t.Errorf("%s: documentation/policy table produced credential candidates: %#v", fixture, candidates)
		}
	}
}

// TestHeaderRowCredentialTableBlankUsername keeps a password-only row
// reviewable without inventing an identity from the header row.
func TestHeaderRowCredentialTableBlankUsername(t *testing.T) {
	manager := loadOfficeRules(t)
	_, candidates := evaluateOfficeFixture(t, manager, "table-h-blank-username.docx", true)
	if !hasOfficeCandidate(candidates, "Orphan-123!", "", "") {
		t.Fatalf("orphan password row was not retained: %#v", candidates)
	}
	for _, candidate := range candidates {
		if candidate.Value == "Orphan-123!" {
			if candidate.Identity != "" {
				t.Fatalf("identity was fabricated for a blank username cell: %#v", candidate)
			}
			if candidate.Verification != credentialanalysis.Review {
				t.Fatalf("orphan password verification = %q, want review", candidate.Verification)
			}
		}
	}
	if !hasOfficeCandidate(candidates, "Two-456!", "user2", "") {
		t.Fatalf("user2 credential was not correlated: %#v", candidates)
	}
}

// TestHeaderRowTableDelimitedParity proves CSV and TSV use the same shared
// table semantics as DOCX.
func TestHeaderRowTableDelimitedParity(t *testing.T) {
	manager := loadOfficeRules(t)
	for _, fixture := range []string{"table-credentials.csv", "table-credentials.tsv"} {
		_, candidates := evaluateOfficeFixture(t, manager, fixture, true)
		for _, want := range []struct{ identity, value string }{
			{"Bob", "Synthetic-Bob-123!"},
			{"Jane", "Synthetic-Jane-456!"},
		} {
			if !hasOfficeCandidate(candidates, want.value, want.identity, "") {
				t.Errorf("%s: %s/%s not surfaced: %#v", fixture, want.identity, want.value, candidates)
			}
		}
		if len(candidates) != 2 {
			t.Errorf("%s: surfaced %d credentials, want 2: %#v", fixture, len(candidates), candidates)
		}
	}
}

// TestHeaderRowCredentialTableProvenance keeps part-level provenance for DOCX
// tables and container provenance for nested ones.
func TestHeaderRowCredentialTableProvenance(t *testing.T) {
	manager := loadOfficeRules(t)
	_, candidates := evaluateOfficeFixture(t, manager, "PasswordList-table.docx", true)
	for _, candidate := range candidates {
		if !strings.Contains(candidate.Path, "PasswordList-table.docx!word/document.xml") {
			t.Errorf("DOCX table provenance lost: %#v", candidate)
		}
	}
	_, nested := evaluateOfficeFixture(t, manager, "nested-password-list.zip", true)
	for _, candidate := range nested {
		if !strings.Contains(candidate.Path, "nested-password-list.zip!PasswordList-table.docx!word/document.xml") {
			t.Errorf("nested container provenance lost: %#v", candidate)
		}
	}
}

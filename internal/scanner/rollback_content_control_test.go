package scanner

import (
	"strings"
	"testing"

	"snablr/internal/officefixture"
)

// TestRollbackPreservesContentControls is the post-rollback safety net: the
// content controls that matter for a live scan must still reach the shared
// harvester after the SMB recovery stack is removed. It uses only synthetic
// values.
func TestRollbackPreservesContentControls(t *testing.T) {
	t.Parallel()
	manager := loadOfficeRules(t)

	cases := []struct {
		name        string
		content     []byte
		wantValue   string
		wantFinding bool
	}{
		{
			name:        "settings.ini",
			content:     []byte("AdminPassword=Synthetic-Admin-123!\n"),
			wantValue:   "Synthetic-Admin-123!",
			wantFinding: true,
		},
		{
			name:        "notes.txt",
			content:     []byte("Password=Synthetic-Txt-123!\n"),
			wantValue:   "Synthetic-Txt-123!",
			wantFinding: true,
		},
		{
			name: "OperationsGuide.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Passordet er; Synthetic-Docx-123!"),
			),
			wantValue:   "Synthetic-Docx-123!",
			wantFinding: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			evaluation, candidates := evaluateInlineFixture(t, manager, tc.name, tc.content)
			if len(candidates) == 0 {
				t.Fatalf("no credential candidate produced from %s", tc.name)
			}
			found := false
			for _, candidate := range candidates {
				if strings.TrimSpace(candidate.Value) == tc.wantValue {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected value %q from %s; candidate values present: %d", tc.wantValue, tc.name, len(candidates))
			}
			if tc.wantFinding && !hasAnyRuleID(evaluation.Findings,
				"content.password_assignment_indicators",
				"content.note_style_credential_pair_indicators",
			) {
				t.Fatalf("no credential content finding for %s: %v", tc.name, ruleIDs(evaluation.Findings))
			}
		})
	}
}

func hasAnyRuleID(findings []Finding, ids ...string) bool {
	for _, id := range ids {
		if hasRuleID(findings, id) {
			return true
		}
	}
	return false
}

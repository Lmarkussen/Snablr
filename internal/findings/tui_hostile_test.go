package findings

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

const finderHostileEvidence = "ok \x1b[2J\x1b[H CLEAR | \x1b(0lqqk DEC | \x1b]0;TITLE\x07 OSC | \u009b31m C1 | x\x08y BS | \u202eRTL | \r CR | © → end"

var finderStyleSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func controlRuneIn(text string) (rune, bool) {
	for _, r := range finderStyleSequence.ReplaceAllString(text, "") {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e {
			return r, true
		}
	}
	return 0, false
}

// Persisted evidence shown in the Finder must not execute terminal control
// sequences, and the accounting and stored data must be unaffected.
func TestFinderDiscoveriesFromHostileEvidenceAreDisplaySafe(t *testing.T) {
	credential := Credential{ID: 7, CredentialKey: "password|svc|p|v", Candidate: credentialanalysis.Candidate{
		Verification: credentialanalysis.Confirmed, CredentialType: "password",
		Identity: "svc\x1b[2J", Value: finderHostileEvidence, Host: "host", Share: "share\x1b(0", Path: "dir/" + finderHostileEvidence,
	}}
	finding := Finding{ID: 41, Finding: scanner.Finding{
		RuleID: "review.rule", RuleName: "Review artifact", Category: "configuration", TriageClass: "review",
		Host: "host", Share: "share", FilePath: "dir/" + finderHostileEvidence, MatchedText: finderHostileEvidence, Context: finderHostileEvidence,
	}}
	categories, audit := buildCategoriesWithAccounting("scan-hostile", []Credential{credential}, []Finding{finding}, nil)
	if audit.UnaccountedRows != 0 {
		t.Fatalf("display sanitising affected accounting: %#v", audit)
	}
	discoveries := 0
	for _, item := range categories {
		for _, d := range item.Discoveries {
			discoveries++
			rendered := strings.Join(append(append([]string{d.Title, d.Identity, d.Value, d.Path, d.Share}, d.Evidence...), d.Sources...), "\n")
			if d.Finding != nil {
				rendered += "\n" + d.Finding.MatchedText + "\n" + d.Finding.Context + "\n" + d.Finding.FilePath
			}
			if r, found := controlRuneIn(rendered); found {
				t.Fatalf("discovery %q carries terminal control %U", d.Title, r)
			}
			for _, ref := range d.PersistedRefs {
				if ref != "credential:7" && ref != "finding:41" && !strings.HasPrefix(ref, "credential:") && !strings.HasPrefix(ref, "finding:") {
					t.Fatalf("lookup ref altered: %q", ref)
				}
			}
		}
	}
	if discoveries == 0 {
		t.Fatal("no discoveries produced")
	}
	if credential.Candidate.Value != finderHostileEvidence || finding.Finding.MatchedText != finderHostileEvidence {
		t.Fatal("persisted data was modified")
	}

	item := safeEvidenceItem(evidenceCacheItem{key: "finding:41", finding: &finding.Finding, candidate: &credential.Candidate, correlation: finderHostileEvidence})
	fetched := fmt.Sprint(item.finding.MatchedText, item.finding.FilePath, item.candidate.Value, item.candidate.Identity, item.correlation)
	if r, found := controlRuneIn(fetched); found {
		t.Fatalf("fetched evidence carries terminal control %U", r)
	}
	if finding.Finding.MatchedText != finderHostileEvidence || credential.Candidate.Value != finderHostileEvidence {
		t.Fatal("fetching evidence modified the persisted data")
	}
}

func TestFinderGlobalSearchRendersHostileResultsSafely(t *testing.T) {
	m := &model{width: 120, height: 32, globalSearchOpen: true, globalSearchQuery: "ok"}
	_, _ = m.Update(globalSearchLoadedMsg{generation: m.globalSearchGeneration, query: m.globalSearchQuery, results: []GlobalSearchResult{
		{Kind: "finding", ID: "1", Field: "finding details", Value: finderHostileEvidence, Context: "/source/" + finderHostileEvidence},
	}})
	if len(m.globalSearchResults) != 1 {
		t.Fatalf("search page not applied: %d results", len(m.globalSearchResults))
	}
	for _, detail := range []bool{false, true} {
		m.globalSearchDetail = detail
		view := m.View()
		if r, found := controlRuneIn(view); found {
			t.Fatalf("global search view (detail=%v) carries terminal control %U", detail, r)
		}
		if !strings.Contains(view, "␛[2J") {
			t.Fatalf("global search view (detail=%v) did not show the evidence in visible form", detail)
		}
		for _, line := range strings.Split(view, "\n") {
			if lipgloss.Width(line) > m.width {
				t.Fatalf("global search line exceeds width: %q", line)
			}
		}
	}
}

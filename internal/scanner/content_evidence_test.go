package scanner

import (
	"strings"
	"testing"

	"snablr/internal/rules"
)

func TestContentEvidenceDoesNotTruncateSnippetOrContext(t *testing.T) {
	content := "prefix=" + strings.Repeat("SENTINEL-", 80) + "\npassword=complete-value\n"
	rule := rules.Rule{
		ID:      "content.synthetic.long_evidence",
		Name:    "Synthetic long evidence",
		Type:    rules.RuleTypeContent,
		Pattern: "password=complete-value",
	}

	details, ok := buildContentMatchDetails(rule, content, 32)
	if !ok {
		t.Fatal("expected synthetic content match")
	}
	wantContext := strings.TrimSpace(content)
	if details.snippet != wantContext || details.context != wantContext {
		t.Fatalf("evidence bytes changed: snippet=%q context=%q want=%q", details.snippet, details.context, wantContext)
	}
	if !strings.Contains(details.snippet, "SENTINEL-") || !strings.Contains(details.snippet, "password=complete-value") {
		t.Fatalf("snippet lost complete evidence: %q", details.snippet)
	}
	if strings.Contains(details.snippet, "...") || strings.Contains(details.context, "...") {
		t.Fatalf("evidence contains truncation marker: snippet=%q context=%q", details.snippet, details.context)
	}
	if !strings.Contains(details.context, "password=complete-value") {
		t.Fatalf("context lost the matched source line: %q", details.context)
	}
}

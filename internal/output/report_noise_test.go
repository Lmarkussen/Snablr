package output

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// Every value, host, share and path in this file is independently invented
// synthetic data. None of it is derived from customer, lab or live scan
// material.

const (
	syntheticEvidenceSecret   = "SyntheticHidden482!"
	syntheticRedactedEvidence = "Password=********"
)

func syntheticEvidenceFinding(context, contextRedacted string) scanner.Finding {
	return scanner.Finding{
		RuleID:              "content.password_assignment_indicators",
		RuleName:            "Synthetic Password Assignment",
		Severity:            "high",
		Confidence:          "medium",
		ConfidenceScore:     55,
		Category:            "credentials",
		Actionable:          true,
		Host:                "synthetic-host.test",
		Share:               "SyntheticShare",
		FilePath:            "configs/synthetic-evidence.ini",
		SignalType:          "content",
		Match:               "password",
		MatchedText:         "Password=" + syntheticEvidenceSecret,
		MatchedTextRedacted: syntheticRedactedEvidence,
		Snippet:             "Password=" + syntheticEvidenceSecret,
		Context:             context,
		ContextRedacted:     contextRedacted,
		LineNumber:          7,
		MatchReason:         "Synthetic content rule matched a password assignment.",
		ConfidenceReasons:   []string{"synthetic content signal strength", "synthetic value quality is plausible"},
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore: 30, ContentSignalStrength: 12, HeuristicSignalContribution: 3,
			PathContextContribution: 5, CorrelationContribution: 5, FinalScore: 55,
			ValueQualityLabel: "medium", ValueQualityScore: 12, ValueQualityReason: "synthetic plausible value",
		},
		SupportingSignals: []scanner.SupportingSignal{{
			SignalType: "content", RuleID: "content.password_assignment_indicators",
			RuleName: "Synthetic Password Assignment", Match: "password",
			Confidence: "medium", Weight: 8, Reason: "synthetic password assignment matched",
		}},
	}
}

func renderSyntheticReport(t *testing.T, findings ...scanner.Finding) string {
	t.Helper()
	var out bytes.Buffer
	writer, err := NewHTMLWriter(&out, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	for _, finding := range findings {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	return out.String()
}

// TestHTMLRedundantEvidenceIsRenderedOnce covers the duplicated-evidence case:
// the raw fields must be gone, the context must be omitted when it only repeats
// the evidence, and the unredacted secret must not survive anywhere in the HTML.
func TestHTMLRedundantEvidenceIsRenderedOnce(t *testing.T) {
	t.Parallel()

	finding := syntheticEvidenceFinding("Password="+syntheticEvidenceSecret, syntheticRedactedEvidence)
	finding.Snippet = "Password=" + syntheticEvidenceSecret
	html := renderSyntheticReport(t, finding)

	if !strings.Contains(html, syntheticRedactedEvidence) {
		t.Fatalf("redacted evidence is missing from the report:\n%s", html)
	}
	if strings.Contains(html, syntheticEvidenceSecret) {
		t.Fatalf("unredacted secret leaked into the HTML report (rendered text, search index or hidden attribute)")
	}
	for _, unwanted := range []string{"Raw Matched Text", "Raw Context", "Context / Snippet"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("redundant evidence label %q is still rendered", unwanted)
		}
	}
	if got := strings.Count(html, `class="evidence-block"`); got != 1 {
		t.Fatalf("evidence blocks rendered = %d, want exactly 1", got)
	}
}

// TestHTMLUsefulContextIsPreservedOnce covers the case where surrounding text
// genuinely adds information: evidence plus one redacted context block, and no
// raw duplicates.
func TestHTMLUsefulContextIsPreservedOnce(t *testing.T) {
	t.Parallel()

	context := "synthetic-line-before\nPassword=" + syntheticEvidenceSecret + "\nsynthetic-line-after"
	contextRedacted := "synthetic-line-before\n" + syntheticRedactedEvidence + "\nsynthetic-line-after"
	html := renderSyntheticReport(t, syntheticEvidenceFinding(context, contextRedacted))

	if !strings.Contains(html, "Context / Snippet") {
		t.Fatalf("useful context was dropped from the report:\n%s", html)
	}
	if !strings.Contains(html, "synthetic-line-before") || !strings.Contains(html, "synthetic-line-after") {
		t.Fatalf("useful context content is missing:\n%s", html)
	}
	if strings.Contains(html, syntheticEvidenceSecret) {
		t.Fatalf("unredacted secret leaked through the context block")
	}
	for _, unwanted := range []string{"Raw Matched Text", "Raw Context"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("raw evidence label %q is still rendered", unwanted)
		}
	}
	if got := strings.Count(html, `class="evidence-block"`); got != 2 {
		t.Fatalf("evidence blocks rendered = %d, want exactly 2 (evidence + context)", got)
	}
}

// TestHTMLTechnicalDetailsAreCollapsedButPreserved covers PROBLEM C: the short
// explanation and confidence stay visible, the scoring material moves behind a
// collapsed block, and nothing is dropped from the report.
func TestHTMLTechnicalDetailsAreCollapsedButPreserved(t *testing.T) {
	t.Parallel()

	html := renderSyntheticReport(t, syntheticEvidenceFinding("", ""))

	if !strings.Contains(html, "Match Reason") {
		t.Fatal("short match reason is not visible")
	}
	if !strings.Contains(html, "medium confidence") {
		t.Fatal("confidence is not visible")
	}
	if !strings.Contains(html, "content.password_assignment_indicators") {
		t.Fatal("rule id is not visible on the finding card")
	}
	if !strings.Contains(html, "Technical details") {
		t.Fatal("technical details section is missing")
	}
	detailsAt := strings.Index(html, `<details class="finding-technical">`)
	if detailsAt < 0 {
		t.Fatalf("technical details are not rendered as a collapsed block:\n%s", html)
	}
	if strings.Contains(html[detailsAt:detailsAt+40], " open") {
		t.Fatal("technical details block is expanded by default")
	}
	for _, want := range []string{"Confidence Reasons", "Confidence Breakdown", "Supporting Signals", "Final score"} {
		at := strings.Index(html, want)
		if at < 0 {
			t.Fatalf("technical detail %q was dropped from the report", want)
		}
		if at < detailsAt {
			t.Fatalf("technical detail %q is rendered outside the collapsed block", want)
		}
	}
	closeAt := strings.Index(html[detailsAt:], "</details>")
	if closeAt < 0 || strings.Index(html, "Confidence Breakdown") > detailsAt+closeAt {
		t.Fatal("confidence breakdown is rendered outside the collapsed technical block")
	}
}

// TestHTMLUnredactedSecretNeverRendersAcrossManyFindings measures the aggregate
// effect: no raw blocks, no unredacted value in any attribute, and far fewer
// evidence blocks than before.
func TestHTMLUnredactedSecretNeverRendersAcrossManyFindings(t *testing.T) {
	t.Parallel()

	findings := make([]scanner.Finding, 0, 40)
	for index := 0; index < 40; index++ {
		finding := syntheticEvidenceFinding("", "")
		finding.FilePath = "configs/synthetic-" + strconv.Itoa(index) + ".ini"
		finding.MatchedText = "Password=" + syntheticEvidenceSecret + strconv.Itoa(index) + "X"
		finding.Snippet = finding.MatchedText
		findings = append(findings, finding)
	}
	html := renderSyntheticReport(t, findings...)

	if strings.Contains(html, syntheticEvidenceSecret) {
		t.Fatal("an unredacted secret reached the HTML report")
	}
	if got := strings.Count(html, "Raw Matched Text"); got != 0 {
		t.Fatalf("Raw Matched Text rendered %d times, want 0", got)
	}
	if got := strings.Count(html, "Raw Context"); got != 0 {
		t.Fatalf("Raw Context rendered %d times, want 0", got)
	}
	if got := strings.Count(html, `class="evidence-block"`); got != len(findings) {
		t.Fatalf("evidence blocks = %d, want %d (one per finding, redundant context omitted)", got, len(findings))
	}
}

// TestCredsOutSuppressesWeakReviewCandidates proves weak review rows never reach
// the explicit sensitive export even though real credentials still do.
func TestCredsOutSuppressesWeakReviewCandidates(t *testing.T) {
	t.Parallel()

	weak := []struct {
		path    string
		content string
	}{
		{"data/synthetic-map.json", `{"cacheToken":"a1","sessionSecret":"b2"}`},
		{"data/synthetic-lines.dat", "token=c3\nsecret=d4\n"},
	}

	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})
	harvested := 0
	for _, item := range weak {
		for _, candidate := range credentialanalysis.Harvest(credentialanalysis.HarvestInput{
			Content: []byte(item.content),
			Path:    item.path,
		}) {
			harvested++
			if err := writer.RecordCredentialCandidate(candidate); err != nil {
				t.Fatal(err)
			}
		}
	}
	if harvested == 0 {
		t.Fatal("the synthetic weak input produced no harvested candidates, so the test proves nothing")
	}
	for _, candidate := range credentialanalysis.Harvest(credentialanalysis.HarvestInput{
		Content: []byte("Password=SyntheticStrong482!\n"),
		Path:    "config/synthetic-strong.env",
	}) {
		if err := writer.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "SyntheticStrong482!") {
		t.Fatalf("real credential was lost from creds-out:\n%s", output)
	}
	if got := reviewCountInCredsOut(t, output); got != 1 {
		t.Fatalf("creds-out review records = %d, want 1 (only the strong credential):\n%s", got, output)
	}
	for _, unwanted := range []string{"Type: token", "Type: secret"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("weak review material %q reached the sensitive export:\n%s", unwanted, output)
		}
	}
}

func reviewCountInCredsOut(t *testing.T, output string) int {
	t.Helper()
	const marker = "==== POTENTIAL CREDENTIAL MATERIAL — REVIEW ===="
	index := strings.Index(output, marker)
	if index < 0 {
		return 0
	}
	rest := output[index:]
	lineIndex := strings.Index(rest, "Count: ")
	if lineIndex < 0 {
		t.Fatalf("no count line after the review marker:\n%s", output)
	}
	rest = rest[lineIndex+len("Count: "):]
	if end := strings.IndexAny(rest, "\r\n"); end >= 0 {
		rest = rest[:end]
	}
	value, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		t.Fatalf("invalid review count %q: %v", rest, err)
	}
	return value
}

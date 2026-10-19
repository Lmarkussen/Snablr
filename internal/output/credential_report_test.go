package output

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// Every host, share, path and value in this file is independently invented
// synthetic data. None of it is derived from customer, lab or live scan
// material.

const (
	syntheticCredentialHost  = "synthetic-host.test"
	syntheticCredentialShare = "SyntheticShare"
)

func syntheticCredentialFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:     "content.password_assignment_indicators",
		RuleName:   "Synthetic Password Assignment",
		Severity:   "high",
		Confidence: "high",
		Category:   "credentials",
		Actionable: true,
		Host:       syntheticCredentialHost,
		Share:      syntheticCredentialShare,
		FilePath:   "configs/synthetic-app.ini",
	}
}

func syntheticCredentialCandidates() []credentialanalysis.Candidate {
	duplicateLocations := []string{
		"configs/one/synthetic-app.ini",
		"configs/two/synthetic-app.ini",
		"configs/three/synthetic-app.ini",
	}
	candidates := []credentialanalysis.Candidate{
		{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "synthetic-user",
			Value:           "SyntheticReal482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            "configs/synthetic-app.ini",
			ValidationBasis: "structured configuration section",
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
		{
			Verification:   credentialanalysis.Review,
			CredentialType: "password",
			Identity:       "USER_TEMPLATE",
			Value:          "PASSWORD_TEMPLATE",
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "configs/synthetic-template.ini",
		},
		{
			Verification:   credentialanalysis.Review,
			CredentialType: "password",
			Identity:       "svc_synthetic",
			Value:          "${APP_PASSWORD}",
			Host:           syntheticCredentialHost,
			Share:          syntheticCredentialShare,
			Path:           "configs/synthetic-braced.env",
		},
	}
	for _, path := range duplicateLocations {
		candidates = append(candidates, credentialanalysis.Candidate{
			Verification:    credentialanalysis.Confirmed,
			CredentialType:  "password",
			Identity:        "svc_duplicate",
			Value:           "SyntheticDuplicate482!",
			Host:            syntheticCredentialHost,
			Share:           syntheticCredentialShare,
			Path:            path,
			ValidationBasis: "structured configuration section",
		})
	}
	return candidates
}

// TestCredentialReportRendersProvenanceAndSuppressesPlaceholders verifies the
// operator-facing HTML credential section: placeholders are absent, provenance
// is visible, duplicate locations aggregate, and wording is truthful.
func TestCredentialReportRendersProvenanceAndSuppressesPlaceholders(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writer, err := NewHTMLWriter(&out, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}

	finding := syntheticCredentialFinding()
	if err := writer.WriteFinding(finding); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range syntheticCredentialCandidates() {
		if err := writer.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	html := out.String()

	// Placeholder identifiers and shapes must be absent from the report.
	for _, unwanted := range []string{"USER_TEMPLATE", "PASSWORD_TEMPLATE", "${APP_PASSWORD}", "%APP_PASS%"} {
		if strings.Contains(html, unwanted) {
			t.Fatalf("placeholder material leaked into the HTML report: %q", unwanted)
		}
	}
	if !strings.Contains(html, "Suppressed Templates / Noise") {
		t.Fatal("report does not surface the suppressed template count")
	}

	// Provenance must be rendered.
	for _, want := range []string{
		syntheticCredentialHost,
		syntheticCredentialShare,
		`\\synthetic-host.test\SyntheticShare\configs\synthetic-app.ini`,
		`\\synthetic-host.test\SyntheticShare\packages\configs.zip!app/settings.ini`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected HTML provenance %q, got:\n%s", want, html)
		}
	}

	// Duplicate locations aggregate into one row with every location retained.
	if got := strings.Count(sectionByID(html, "credential-analysis"), "svc_duplicate"); got != 1 {
		t.Fatalf("duplicate credential rendered %d rows, want 1:\n%s", got, html)
	}
	for _, location := range []string{
		`\\synthetic-host.test\SyntheticShare\configs\one\synthetic-app.ini`,
		`\\synthetic-host.test\SyntheticShare\configs\two\synthetic-app.ini`,
		`\\synthetic-host.test\SyntheticShare\configs\three\synthetic-app.ini`,
	} {
		if !strings.Contains(html, location) {
			t.Fatalf("aggregated credential lost location %q:\n%s", location, html)
		}
	}
	if !strings.Contains(html, "3 observations") {
		t.Fatalf("aggregated credential did not report its occurrence count:\n%s", html)
	}

	// Truthful validation wording.
	if !strings.Contains(html, "cryptographically recovered") || !strings.Contains(html, "structurally parsed explicit credential") {
		t.Fatalf("validation wording does not distinguish recovery from parsing:\n%s", html)
	}
	if strings.Contains(html, "Validated by offline structure or cryptographic recovery") {
		t.Fatal("misleading credential wording is still rendered")
	}

	// Finding linkage and explicit independent-harvest status.
	anchor := findingAnchor(finding)
	if !strings.Contains(html, `href="#`+anchor+`"`) || !strings.Contains(html, `id="`+anchor+`"`) {
		t.Fatalf("credential row was not linked to its finding card %q:\n%s", anchor, html)
	}
	if got := strings.Count(html, `id="`+anchor+`"`); got != 1 {
		t.Fatalf("finding anchor %q rendered %d times, want 1", anchor, got)
	}
	if !strings.Contains(html, "no corresponding finding card") {
		t.Fatalf("independent credential rows must state that no card exists:\n%s", html)
	}
}

// TestCredentialRowLinksSupportingFindingCard proves the linkage also works for
// findings that are rendered in the supporting (non-actionable) section.
func TestCredentialRowLinksSupportingFindingCard(t *testing.T) {
	t.Parallel()

	finding := syntheticCredentialFinding()
	finding.Actionable = false
	finding.Severity = "low"

	var out bytes.Buffer
	writer, err := NewHTMLWriter(&out, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(finding); err != nil {
		t.Fatal(err)
	}
	if err := writer.RecordCredentialCandidate(credentialanalysis.Candidate{
		Verification:    credentialanalysis.Confirmed,
		CredentialType:  "password",
		Identity:        "synthetic-user",
		Value:           "SyntheticReal482!",
		Host:            syntheticCredentialHost,
		Share:           syntheticCredentialShare,
		Path:            "configs/synthetic-app.ini",
		ValidationBasis: "structured configuration section",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	html := out.String()
	anchor := findingAnchor(finding)
	if !strings.Contains(html, `href="#`+anchor+`"`) {
		t.Fatalf("supporting finding card was not linked %q:\n%s", anchor, html)
	}
	if got := strings.Count(html, `id="`+anchor+`"`); got != 1 {
		t.Fatalf("supporting finding anchor %q rendered %d times, want 1", anchor, got)
	}
}

// TestCredsOutSuppressesPlaceholdersAndKeepsRealSecrets verifies the explicit
// sensitive export never carries placeholder material while real credentials
// remain present.
func TestCredsOutSuppressesPlaceholdersAndKeepsRealSecrets(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})
	for _, candidate := range syntheticCredentialCandidates() {
		if err := writer.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output := buf.String()

	for _, want := range []string{
		"SyntheticReal482!",
		"SyntheticArchive482!",
		"SyntheticDuplicate482!",
		`\\synthetic-host.test\SyntheticShare\packages\configs.zip!app/settings.ini`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("creds-out lost real credential material %q:\n%s", want, output)
		}
	}
	for _, unwanted := range []string{"USER_TEMPLATE", "PASSWORD_TEMPLATE", "${APP_PASSWORD}"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("placeholders leaked into creds-out: %q\n%s", unwanted, output)
		}
	}
}

func TestCredsOutIncludesNetNTLMMaterial(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})
	candidate := credentialanalysis.Candidate{
		Verification:    credentialanalysis.Confirmed,
		CredentialType:  "netntlmv2",
		Identity:        "synthetic-user",
		Domain:          "SYNTHETIC",
		Value:           "synthetic-user::SYNTHETIC:a1b2c3d4e5f60718:00112233445566778899aabbccddeeff:01010000000000000102030405060708090a0b0c0d0e0f10",
		Path:            "captures/netntlm.txt",
		ValidationBasis: "structured_netntlmv2_record",
	}
	if err := writer.RecordCredentialCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Type: netntlmv2", "Identity: synthetic-user", candidate.Value} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("NetNTLM material missing from creds-out (%q):\n%s", want, buf.String())
		}
	}
}

// TestCredentialReviewSectionIsBounded proves a large review set cannot flood
// the top of the report with thousands of rows while the underlying data stays
// available to the non-HTML exports.
func TestCredentialReviewSectionIsBounded(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writer, err := NewHTMLWriter(&out, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	for index := 0; index < 250; index++ {
		value := "Synthetic-Review-" + strings.Repeat("x", index%5) + "482!"
		candidate := credentialanalysis.Candidate{
			Verification:   credentialanalysis.Review,
			CredentialType: "password",
			Value:          value + string(rune('a'+index%26)) + strconv.Itoa(index),
			Path:           "configs/review-" + strconv.Itoa(index) + ".ini",
			ReviewReasons:  []string{"credential-like value requires semantic review"},
		}
		if err := writer.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	html := out.String()
	if !strings.Contains(html, "Showing the first 200 of 250 review records") {
		t.Fatalf("review section is not bounded with an explicit notice:\n%s", html)
	}
	if got := strings.Count(html, `class="credential-row review-row"`); got != maxReviewRows {
		t.Fatalf("review rows rendered = %d, want %d", got, maxReviewRows)
	}
}

// TestCredsOutRejectsPlaceholderConnectionStringFinding proves a
// finding-derived connection string built only from placeholders never reaches
// the sensitive export, while a real one still does.
func TestCredsOutRejectsPlaceholderConnectionStringFinding(t *testing.T) {
	t.Parallel()

	findingFor := func(connection string) scanner.Finding {
		return scanner.Finding{
			RuleID:      "dbinspect.access.connection_string",
			RuleName:    "Validated Database Connection Details",
			Severity:    "high",
			Confidence:  "high",
			Category:    "database-access",
			Actionable:  true,
			Host:        syntheticCredentialHost,
			Share:       syntheticCredentialShare,
			FilePath:    "configs/synthetic-db.config",
			MatchedText: connection,
		}
	}

	var placeholderOut bytes.Buffer
	placeholderWriter := NewCredsWriter(&placeholderOut, nopCloser{})
	if err := placeholderWriter.WriteFinding(findingFor("Server=SERVER_TEMPLATE;User ID=USER_TEMPLATE;Password=PASSWORD_TEMPLATE;")); err != nil {
		t.Fatal(err)
	}
	if err := placeholderWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"PASSWORD_TEMPLATE", "USER_TEMPLATE", "SERVER_TEMPLATE"} {
		if strings.Contains(placeholderOut.String(), unwanted) {
			t.Fatalf("placeholder connection string reached creds-out: %q\n%s", unwanted, placeholderOut.String())
		}
	}

	var realOut bytes.Buffer
	realWriter := NewCredsWriter(&realOut, nopCloser{})
	if err := realWriter.WriteFinding(findingFor("Server=db.synthetic.test;User ID=svc_synthetic;Password=SyntheticDB482!;")); err != nil {
		t.Fatal(err)
	}
	if err := realWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(realOut.String(), "SyntheticDB482!") {
		t.Fatalf("real connection string credential was lost from creds-out:\n%s", realOut.String())
	}
}

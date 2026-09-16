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

// candidateForValue returns the first candidate carrying the value.
func candidateForValue(candidates []credentialanalysis.Candidate, value string) *credentialanalysis.Candidate {
	for index := range candidates {
		if candidates[index].Value == value {
			return &candidates[index]
		}
	}
	return nil
}

func evaluateInlineFixture(t *testing.T, manager *rules.Manager, name string, content []byte) (Evaluation, []credentialanalysis.Candidate) {
	t.Helper()
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		Host: "fs01", Share: "share", FilePath: name, Name: name,
		Extension: filepath.Ext(name), Size: int64(len(content)),
	}, content)
	return evaluation, collector.candidates
}

// TestNaturalLanguageCredentialFormats is the format-parity regression for the
// shared grammar: the same expression must work through DOCX, legacy DOC and
// plain text, and produce the existing actionable content finding.
func TestNaturalLanguageCredentialFormats(t *testing.T) {
	manager := loadOfficeRules(t)
	cases := []struct {
		name      string
		path      string
		content   []byte
		value     string
		identity  string
		confirmed bool
	}{
		{
			name: "docx sentence-style",
			path: "NaturalLanguageCredential-synthetic.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Brukernavn er; svc_example"),
				officefixture.Paragraph("Passordet er; Synthetic-Example-123!"),
			),
			value: "Synthetic-Example-123!", identity: "svc_example", confirmed: true,
		},
		{
			name: "docx split runs",
			path: "NaturalLanguageCredential-split.docx",
			content: officefixture.DOCXWithParts(nil,
				officefixture.RunParagraph("Pass", "ordet", " er", "; ", "Synthetic-Split-123!"),
			),
			value: "Synthetic-Split-123!", confirmed: false,
		},
		{
			name: "docx english",
			path: "english-sentence.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Username is; svc_eng"),
				officefixture.Paragraph("Password is; Synthetic-English-123!"),
			),
			value: "Synthetic-English-123!", identity: "svc_eng", confirmed: true,
		},
		{
			name: "docx next line",
			path: "next-line.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Brukernavn er; svc_next"),
				officefixture.Paragraph("Passordet er:"),
				officefixture.Paragraph("Synthetic-NextLine-123!"),
			),
			value: "Synthetic-NextLine-123!", identity: "svc_next", confirmed: true,
		},
		{
			name:    "legacy doc",
			path:    "synthetic-sentences.doc",
			content: legacyfixture.Word("Brukernavn er; svc_legacy\rPassordet er; Synthetic-Legacy-123!\r"),
			value:   "Synthetic-Legacy-123!", identity: "svc_legacy", confirmed: true,
		},
		{
			name:     "plain text",
			path:     "PasswordList.txt",
			content:  []byte("Brukernavn er; svc_txt\nPassordet er; Synthetic-Txt-123!\n"),
			value:    "Synthetic-Txt-123!",
			identity: "",
			// Plain text without a section keeps the established review policy.
			confirmed: false,
		},
		{
			name:      "utf8 norwegian",
			path:      "utf8-sentences.txt",
			content:   []byte("Brukernavn er; bruker-Ø\nPassordet er; Hemmelig-ÆØÅ-123!\n"),
			value:     "Hemmelig-ÆØÅ-123!",
			identity:  "",
			confirmed: false,
		},
		{
			// Strong explicit syntax carries short values in every format.
			name: "docx short explicit value",
			path: "NaturalLanguageVariants.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Brukernavnet er; user1"),
				officefixture.Paragraph("Passordet er; 8392"),
			),
			value: "8392", identity: "user1", confirmed: true,
		},
		{
			name: "docx prefix expression",
			path: "NaturalLanguageVariants-prefix.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Lokal innlogging. Passordet er; Synthetic-One-123!"),
			),
			value: "Synthetic-One-123!", confirmed: false,
		},
		{
			name: "docx subject expression",
			path: "NaturalLanguageVariants-subject.docx",
			content: officefixture.DOCX(
				officefixture.Paragraph("Passordet for VPN er; Synthetic-Net-123!"),
			),
			value: "Synthetic-Net-123!", confirmed: false,
		},
		{
			name:    "legacy doc short explicit value",
			path:    "NaturalLanguageVariants.doc",
			content: legacyfixture.Word("Brukeren er; user3\rPassordet er; 7319\r"),
			value:   "7319", identity: "user3", confirmed: true,
		},
		{
			name:    "legacy doc subject expression",
			path:    "NaturalLanguageVariants-subject.doc",
			content: legacyfixture.Word("Lokal innlogging.\rPassordet for nettverket er; Synthetic-Legacy-Net-123!\r"),
			value:   "Synthetic-Legacy-Net-123!", confirmed: false,
		},
		{
			name:      "plain text short explicit value",
			path:      "NaturalLanguageVariants.txt",
			content:   []byte("Passordet er; 8392\n"),
			value:     "8392",
			identity:  "",
			confirmed: false,
		},
		{
			name:      "plain text subject expression",
			path:      "NaturalLanguageVariants-subject.txt",
			content:   []byte("Login information. Password for VPN is; Synthetic-English-123!\n"),
			value:     "Synthetic-English-123!",
			identity:  "",
			confirmed: false,
		},
	}
	for _, test := range cases {
		evaluation, candidates := evaluateInlineFixture(t, manager, test.path, test.content)
		candidate := candidateForValue(candidates, test.value)
		if candidate == nil {
			t.Errorf("%s: expression value %q was not surfaced: %#v", test.name, test.value, candidates)
			continue
		}
		if candidate.CredentialType != "password" {
			t.Errorf("%s: credential type = %q, want password", test.name, candidate.CredentialType)
		}
		if test.identity != "" && candidate.Identity != test.identity {
			t.Errorf("%s: identity = %q, want %q", test.name, candidate.Identity, test.identity)
		}
		if test.confirmed && candidate.Verification != credentialanalysis.Confirmed {
			t.Errorf("%s: verification = %q, want confirmed", test.name, candidate.Verification)
		}
		found := hasRuleID(evaluation.Findings, "content.password_assignment_indicators")
		if !found {
			t.Errorf("%s: natural-language assignment produced no content finding: %v", test.name, ruleIDs(evaluation.Findings))
		}
	}
}

// TestShortExplicitAssignmentPolicy pins the reporting decision for explicit
// short passwords. An explicit "<password> = <value>" statement asserts a
// credential outright, so shortness alone no longer withholds the finding; the
// value has already passed the bounded grammar. Placeholder-like and low-entropy
// values are still suppressed, so the exception stays narrow.
func TestShortExplicitAssignmentPolicy(t *testing.T) {
	manager := loadOfficeRules(t)
	normalised := credentialanalysis.NormalizeCredentialExpressions("Passordet er; 8392")
	if normalised != "Passord=8392" {
		t.Fatalf("short explicit expression was not normalised into the shared assignment form: %q", normalised)
	}

	engine := NewEngine(Options{}, manager, nil, nil)
	matched := false
	for _, rule := range engine.contentRules {
		if rule.ID != "content.password_assignment_indicators" {
			continue
		}
		rx, err := compiledPattern(rule)
		if err != nil {
			t.Fatalf("rule pattern did not compile: %v", err)
		}
		if len(contentMatchRange(rule.ID, rx, normalised)) == 2 {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("content rule did not match the normalised short assignment %q", normalised)
	}

	evaluation, candidates := evaluateInlineFixture(t, manager, "NaturalLanguageVariants.txt", []byte("Passordet er; 8392\n"))
	if candidateForValue(candidates, "8392") == nil {
		t.Fatalf("short explicit credential was not harvested: %#v", candidates)
	}
	if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
		t.Fatalf("short explicit credential produced no actionable finding: %v", ruleIDs(evaluation.Findings))
	}

	// Placeholder-like and low-entropy explicit assignments stay suppressed.
	for _, line := range []string{
		"Passordet er; changeme\n",
		"Passordet er; aaaaaaaa\n",
		"Passordet er; example\n",
	} {
		evaluation, _ := evaluateInlineFixture(t, manager, "NaturalLanguageVariants.txt", []byte(line))
		if hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
			t.Errorf("weak explicit assignment produced a finding: %q -> %v", strings.TrimSpace(line), ruleIDs(evaluation.Findings))
		}
	}

	// The exception is scoped to password assignments: a short secret assignment
	// keeps the established suppression.
	secretEvaluation, _ := evaluateInlineFixture(t, manager, "NaturalLanguageVariants.txt", []byte("secret=abc123\n"))
	if hasRuleID(secretEvaluation.Findings, "content.secret_assignment_indicators") {
		t.Errorf("short secret assignment was no longer suppressed: %v", ruleIDs(secretEvaluation.Findings))
	}
}

// TestNaturalLanguageNegativeFormats proves prose stays inert in every format.
func TestNaturalLanguageNegativeFormats(t *testing.T) {
	manager := loadOfficeRules(t)
	prose := []string{
		"Passordet er viktig å bytte regelmessig.",
		"Passordet er minimum 14 tegn.",
		"Passord er påkrevd.",
		"Passordet er definert av policy.",
		"Passordet for systemet er definert av policy.",
		"Passordet for brukere må endres hver måned.",
		"Password is required.",
		"Password is case sensitive.",
		"Password is case-sensitive.",
		"Password is defined by policy.",
		"Password for users must be changed monthly.",
	}
	for _, line := range prose {
		if _, candidates := evaluateInlineFixture(t, manager, "prose.docx", officefixture.DOCX(officefixture.Paragraph(line))); len(candidates) != 0 {
			t.Errorf("DOCX prose produced candidates: %q -> %#v", line, candidates)
		}
		if _, candidates := evaluateInlineFixture(t, manager, "prose.doc", legacyfixture.Word(line+"\r")); len(candidates) != 0 {
			t.Errorf("legacy DOC prose produced candidates: %q -> %#v", line, candidates)
		}
		if _, candidates := evaluateInlineFixture(t, manager, "prose.txt", []byte(line+"\n")); len(candidates) != 0 {
			t.Errorf("TXT prose produced candidates: %q -> %#v", line, candidates)
		}
	}
}

// TestNaturalLanguageCredentialReachesPostScanAndCredsOut proves the recovered
// expression flows into the shared analysis model without duplicates.
func TestNaturalLanguageCredentialReachesPostScanAndCredsOut(t *testing.T) {
	manager := loadOfficeRules(t)
	docx := officefixture.DOCX(
		officefixture.Paragraph("Brukernavn er; svc_example"),
		officefixture.Paragraph("Passordet er; Synthetic-Example-123!"),
	)
	evaluation, candidates := evaluateInlineFixture(t, manager, "NaturalLanguageCredential-synthetic.docx", docx)
	report := credentialanalysis.Analyze(candidates)
	if len(report.Candidates) == 0 {
		t.Fatal("no logical credential was produced")
	}
	seen := map[string]int{}
	for _, candidate := range report.Candidates {
		seen[candidate.Value]++
	}
	for value, count := range seen {
		if count != 1 {
			t.Errorf("logical credential %q reported %d times", value, count)
		}
	}
	for _, candidate := range report.Confirmed {
		if candidate.Identity != "svc_example" {
			t.Errorf("confirmed identity = %q, want svc_example", candidate.Identity)
		}
		if !strings.EqualFold(candidate.CredentialType, "password") {
			t.Errorf("credential type = %q, want password", candidate.CredentialType)
		}
	}
	if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
		t.Fatalf("no actionable content finding: %v", ruleIDs(evaluation.Findings))
	}
}

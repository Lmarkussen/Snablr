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
		if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
			t.Errorf("%s: natural-language assignment produced no content finding: %v", test.name, ruleIDs(evaluation.Findings))
		}
	}
}

// TestNaturalLanguageNegativeFormats proves prose stays inert in every format.
func TestNaturalLanguageNegativeFormats(t *testing.T) {
	manager := loadOfficeRules(t)
	prose := []string{
		"Passordet er viktig å bytte regelmessig.",
		"Passordet er minimum 14 tegn.",
		"Passord er påkrevd.",
		"Password is required.",
		"Password is case sensitive.",
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

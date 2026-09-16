package scanner

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"snablr/internal/credentialanalysis"
)

// legacyWordBytes simulates a legacy binary Office document at signature level:
// an OLE2 header followed by a WordDocument-like stream whose text is UTF-16LE.
// It exists to pin current behaviour (no OLE/legacy parser, so no content
// extraction); it is not a byte-exact Word 97 document.
func legacyWordBytes(text string) []byte {
	var buffer bytes.Buffer
	buffer.Write([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00})
	buffer.Write(bytes.Repeat([]byte{0x00, 0x00, 0x0A, 0x00}, 24))
	encoded := utf16.Encode([]rune(text))
	raw := make([]byte, 2)
	for _, value := range encoded {
		binary.LittleEndian.PutUint16(raw, value)
		buffer.Write(raw)
	}
	buffer.Write(bytes.Repeat([]byte{0x00, 0xFF, 0x13, 0x00}, 24))
	return buffer.Bytes()
}

// TestLivePasswordListFilenameOracle is the regression for the live filename
// shape "PasswordList": a leading number, a space, and any capitalisation
// must not defeat discovery. Discovery is a hint only and never creates a
// credential by itself.
func TestLivePasswordListFilenameOracle(t *testing.T) {
	manager := loadOfficeRules(t)
	names := []string{
		"passordliste-eksempel.docx",
		"passordliste-eksempel.xlsx",
		"PasswordList.txt",
		"passordliste-eksempel.doc",
		"passordliste-eksempel.xls",
		"PasswordList.pdf",
		"PasswordList",
		"Passordliste",
		"1 Passordliste.txt",
		"0PasswordList.txt",
		"2024 Passordliste.txt",
		"01-Passordliste.txt",
		"01_Passordliste.txt",
		"01.Passordliste.txt",
		"01  Passordliste.txt",
		"passwordlist.txt",
		"PASSWORDLIST.txt",
		"01 Passord Liste.txt",
		"01 Password List.txt",
		"PasswordLists/PasswordList.txt",
	}
	for _, name := range names {
		collector := &recordingCandidateSink{}
		engine := NewEngine(Options{}, manager, nil, nil)
		engine.SetCredentialCandidateSink(collector)
		// Filename-only evaluation: no content is supplied, so any credential
		// candidate here would be a filename-derived false positive.
		evaluation := engine.Evaluate(FileMetadata{
			FilePath: "Dokumenter/" + name, Name: filepath.Base(name),
			Extension: filepath.Ext(name), Size: 4096,
		}, nil)
		if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
			// English password-list names are intentionally covered by the
			// existing English rule instead.
			if !strings.Contains(strings.ToLower(name), "password") ||
				!hasRuleID(evaluation.Findings, "filename.credentials_and_secrets_keywords") {
				t.Errorf("%s: password-list filename rule did not match (rules=%v)", name, ruleIDs(evaluation.Findings))
			}
		}
		if len(collector.candidates) != 0 {
			t.Errorf("%s: filename alone produced credential candidates: %#v", name, collector.candidates)
		}
	}
}

// TestLivePasswordListFilenameNegativesStayUnpromoted keeps policy and
// documentation naming out of the strong Norwegian password-list rule.
func TestLivePasswordListFilenameNegativesStayUnpromoted(t *testing.T) {
	manager := loadOfficeRules(t)
	for _, name := range []string{
		"passordpolicy.docx",
		"passordkrav.docx",
		"passordrutiner.txt",
		"veiledning-for-passord.docx",
	} {
		engine := NewEngine(Options{}, manager, nil, nil)
		evaluation := engine.Evaluate(FileMetadata{
			FilePath: "Dokumenter/" + name, Name: name,
			Extension: filepath.Ext(name), Size: 4096,
		}, nil)
		if hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") ||
			hasRuleID(evaluation.Findings, "filename.norwegian_credential_review_keywords") {
			t.Errorf("%s: policy/documentation filename was over-promoted: %v", name, ruleIDs(evaluation.Findings))
		}
	}
}

// TestLivePasswordListContentIsHarvested is the exact content regression for the
// live file shape. Before the secondary-part fix these variants produced no
// candidate at all because their text lives in rendered parts that were never
// inspected.
func TestLivePasswordListContentIsHarvested(t *testing.T) {
	manager := loadOfficeRules(t)
	cases := []struct {
		fixture  string
		value    string
		identity string
		part     string
		verified credentialanalysis.Verification
	}{
		{"passordliste-eksempel.docx", "Test-Hemmelig-123!", "svc_test", "word/document.xml", credentialanalysis.Confirmed},
		{"passordliste-eksempel.xlsx", "Excel-Hemmelig-123!", "svc_excel", "xl/worksheets/sheet1.xml", credentialanalysis.Confirmed},
		{"PasswordList-footnote.docx", "Fotnote-Hemmelig-123!", "svc_foot", "word/footnotes.xml", credentialanalysis.Confirmed},
		{"PasswordList-comment.docx", "Kommentar-Hemmelig-123!", "svc_kommentar", "word/comments.xml", credentialanalysis.Confirmed},
		{"PasswordList-smartart.docx", "SmartArt-Hemmelig-123!", "svc_smart", "word/diagrams/data1.xml", credentialanalysis.Confirmed},
		{"PasswordList-comment.xlsx", "ExcelKommentar-Hemmelig-123!", "svc_excel_kommentar", "xl/comments1.xml", credentialanalysis.Confirmed},
		{"PasswordList-drawing.xlsx", "Tegning-Hemmelig-123!", "svc_tegning", "xl/drawings/drawing1.xml", credentialanalysis.Confirmed},
		// Plain text without a section keeps the established review-only policy
		// for section-less top-level lines; the value must still be surfaced.
		{"PasswordList.txt", "Txt-Hemmelig-123!", "", "", credentialanalysis.Review},
	}
	for _, test := range cases {
		evaluation, candidates := evaluateOfficeFixture(t, manager, test.fixture, true)
		found := false
		for _, candidate := range candidates {
			if candidate.Value != test.value {
				continue
			}
			found = true
			if candidate.Verification != test.verified {
				t.Errorf("%s: verification = %q, want %q", test.fixture, candidate.Verification, test.verified)
			}
			if test.identity != "" && candidate.Identity != test.identity {
				t.Errorf("%s: identity = %q, want %q", test.fixture, candidate.Identity, test.identity)
			}
			if test.part != "" && !strings.Contains(candidate.Path, test.part) {
				t.Errorf("%s: provenance %q does not name the rendered part %q", test.fixture, candidate.Path, test.part)
			}
		}
		if !found {
			t.Errorf("%s: credential %q was not surfaced from %s", test.fixture, test.value, test.part)
		}
		if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
			t.Errorf("%s: no content finding for the rendered credential text", test.fixture)
		}
	}
}

// TestLegacyOfficeAndBinaryContentRemainUnsupported documents the confirmed
// legacy gap: Snablr has no OLE/legacy-Office parser, so .doc/.xls content is
// not extracted. Filename discovery must still work for those files.
func TestLegacyOfficeAndBinaryContentRemainUnsupported(t *testing.T) {
	manager := loadOfficeRules(t)
	for _, name := range []string{"passordliste-eksempel.doc", "passordliste-eksempel.xls"} {
		content := legacyWordBytes("Brukernavn: svc_legacy\rPassord: Legacy-Hemmelig-123!\r")
		collector := &recordingCandidateSink{}
		engine := NewEngine(Options{}, manager, nil, nil)
		engine.SetCredentialCandidateSink(collector)
		evaluation := engine.Evaluate(FileMetadata{
			FilePath: "Dokumenter/" + name, Name: name,
			Extension: filepath.Ext(name), Size: int64(len(content)),
		}, content)
		if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
			t.Errorf("%s: filename discovery must still work without content support", name)
		}
		if len(collector.candidates) != 0 {
			t.Errorf("%s: unexpected legacy content extraction: %#v", name, collector.candidates)
		}
	}
}

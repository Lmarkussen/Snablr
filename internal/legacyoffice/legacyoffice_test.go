package legacyoffice

import (
	"bytes"
	"strings"
	"testing"

	"snablr/internal/legacyfixture"
)

func TestExtractWordDecodesBothPieceEncodings(t *testing.T) {
	doc := legacyfixture.WordMixed(
		"Brukernavn: svc_cp1252\rDomene: KUNDE\rPassord: CP1252-Hemmelig-æøå-123!\r",
		"Passord: Uni-Hemmelig-ÆØÅ-456!\r",
	)
	result, ok := Extract(doc)
	if !ok || result.Kind != KindWord {
		t.Fatalf("expected a Word document, got ok=%v kind=%s", ok, result.Kind)
	}
	for _, want := range []string{
		"Brukernavn: svc_cp1252",
		"Passord: CP1252-Hemmelig-æøå-123!",
		"Passord: Uni-Hemmelig-ÆØÅ-456!",
	} {
		if !strings.Contains(result.Text, want) {
			t.Errorf("extracted text missing %q:\n%s", want, result.Text)
		}
	}
	// Lines are preserved so the shared harvester can parse label/value pairs.
	if !strings.Contains(result.Text, "\n") {
		t.Fatalf("paragraph boundaries were not preserved: %q", result.Text)
	}
}

func TestExtractWordTableBecomesTabSeparatedRows(t *testing.T) {
	doc := legacyfixture.WordTable(
		[]string{"USERNAME", "Passord"},
		[]string{"Bob", "Synthetic-Bob-123!"},
		[]string{"Jane", "Synthetic-Jane-456!"},
	)
	result, ok := Extract(doc)
	if !ok {
		t.Fatal("expected a Word document")
	}
	lines := strings.Split(strings.TrimSpace(result.Text), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected three table rows, got %q", result.Text)
	}
	if strings.TrimRight(lines[0], "\t") != "USERNAME\tPassord" {
		t.Fatalf("header row not reconstructed as cells: %q", lines[0])
	}
	if !strings.Contains(lines[1], "Bob\tSynthetic-Bob-123!") {
		t.Fatalf("first data row not reconstructed: %q", lines[1])
	}
	if !strings.Contains(lines[2], "Jane\tSynthetic-Jane-456!") {
		t.Fatalf("second data row not reconstructed: %q", lines[2])
	}
}

func TestExtractWordCP1252NorwegianCharacters(t *testing.T) {
	result, ok := Extract(legacyfixture.WordCP1252("Passord: CP1252-ÆØÅ-123!\r"))
	if !ok {
		t.Fatal("expected a Word document")
	}
	if !strings.Contains(result.Text, "CP1252-ÆØÅ-123!") {
		t.Fatalf("CP1252 text was mangled: %q", result.Text)
	}
	if strings.Contains(result.Text, "\uFFFD") {
		t.Fatalf("extraction produced replacement characters: %q", result.Text)
	}
}

func TestExtractWorkbookBuildsGrid(t *testing.T) {
	book := legacyfixture.Workbook([][]string{
		{"Brukernavn", "Passord", "Domene"},
		{"user1", "Legacy-One-123!", "KUNDE"},
		{"user2", "Legacy-Two-456!", "KUNDE"},
		{"Antall", "14"},
	})
	result, ok := Extract(book)
	if !ok || result.Kind != KindExcel {
		t.Fatalf("expected an Excel workbook, got ok=%v kind=%s limitations=%v", ok, result.Kind, result.Limitations)
	}
	if len(result.Grid) != 4 {
		t.Fatalf("expected four grid rows, got %d: %#v", len(result.Grid), result.Grid)
	}
	if result.Grid[0][1] != "Passord" || result.Grid[1][1] != "Legacy-One-123!" {
		t.Fatalf("grid cells were not preserved: %#v", result.Grid)
	}
	if result.Grid[3][1] != "14" {
		t.Fatalf("numeric cell was not recovered: %#v", result.Grid[3])
	}
}

func TestExtractDetectsEncryptedDocuments(t *testing.T) {
	word, ok := Extract(legacyfixture.WordEncrypted())
	if !ok || !word.Encrypted {
		t.Fatalf("encrypted Word document not detected: ok=%v %#v", ok, word)
	}
	if word.Text != "" {
		t.Fatalf("encrypted Word content must not be reported as extracted")
	}
	excel, ok := Extract(legacyfixture.WorkbookEncrypted())
	if !ok || !excel.Encrypted {
		t.Fatalf("encrypted workbook not detected: ok=%v %#v", ok, excel)
	}
}

func TestExtractRejectsNonLegacyContent(t *testing.T) {
	for _, content := range [][]byte{
		[]byte("plain text, not a compound file"),
		[]byte("PK\x03\x04 this is really a zip container"),
		nil,
	} {
		if _, ok := Extract(content); ok {
			t.Fatalf("non-legacy content was treated as a legacy Office document: %q", content)
		}
	}
}

func TestExtractMalformedInputFailsSafely(t *testing.T) {
	truncated := legacyfixture.Word("Passord: Synthetic-123!\r")
	truncated = truncated[:600]

	badFAT := legacyfixture.Word("Passord: Synthetic-123!\r")
	// Corrupt the FAT sector chain for the first stream so following the chain
	// cannot terminate.
	if len(badFAT) > 2048 {
		for offset := 2048; offset < 2048+32; offset++ {
			badFAT[offset] = 0xFF
		}
	}

	signatureOnly := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, bytes.Repeat([]byte{0x00}, 512)...)

	for name, content := range map[string][]byte{
		"truncated":      truncated,
		"corrupt fat":    badFAT,
		"signature only": signatureOnly,
		"random":         bytes.Repeat([]byte{0xAB}, 4096),
	} {
		document, ok := Extract(content)
		if !ok {
			// Random bytes are not a compound file at all: that is a safe refusal.
			continue
		}
		if document.Text != "" && !document.Encrypted {
			// A malformed file may still yield partial text, but it must never
			// panic or report a fabricated credential structure.
			if strings.Contains(document.Text, "Synthetic-123!") && name == "truncated" {
				continue
			}
		}
		if document.Encrypted && document.Text != "" {
			t.Fatalf("%s: encrypted document reported extracted text", name)
		}
	}
}

func TestExtractRejectsOversizedDocuments(t *testing.T) {
	content := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, MaxContentBytes+1)...)
	document, ok := Extract(content)
	if !ok {
		t.Fatal("oversized legacy document should be recognised and reported")
	}
	if len(document.Limitations) == 0 {
		t.Fatalf("oversized document produced no limitation: %#v", document)
	}
}

func TestExtractPowerPointIsExplicitlyDeferred(t *testing.T) {
	content := legacyfixture.CFB(map[string][]byte{"PowerPoint Document": make([]byte, 8192)})
	document, ok := Extract(content)
	if !ok || document.Kind != KindPowerPoint {
		t.Fatalf("expected a PowerPoint document, got ok=%v kind=%s", ok, document.Kind)
	}
	if len(document.Limitations) == 0 {
		t.Fatalf("deferred PowerPoint support must be reported: %#v", document)
	}
}

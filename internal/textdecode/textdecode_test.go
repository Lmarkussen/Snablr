package textdecode

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func TestDecodePreservesValidUTF8(t *testing.T) {
	t.Parallel()

	input := []byte("Passord: blåbær æøå\r\nSeñor niño\n")
	got, ok := Decode(input)
	if !ok {
		t.Fatal("expected valid UTF-8 input to decode")
	}
	want := "Passord: blåbær æøå\nSeñor niño\n"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestDecodeUTF16LEWithoutBOM(t *testing.T) {
	t.Parallel()

	input := utf16Bytes("Passord: blåbær æøå\n", binary.LittleEndian, false)
	got, ok := Decode(input)
	if !ok {
		t.Fatal("expected UTF-16LE input to decode")
	}
	if got != "Passord: blåbær æøå\n" {
		t.Fatalf("unexpected UTF-16LE decode result: %q", got)
	}
}

func TestDecodeUTF16BEWithBOM(t *testing.T) {
	t.Parallel()

	input := utf16Bytes("Español: niño áéíóú\n", binary.BigEndian, true)
	got, ok := Decode(input)
	if !ok {
		t.Fatal("expected UTF-16BE input to decode")
	}
	if got != "Español: niño áéíóú\n" {
		t.Fatalf("unexpected UTF-16BE decode result: %q", got)
	}
}

func TestDecodeWindows1252(t *testing.T) {
	t.Parallel()

	input := mustEncodeSingleByte(t, charmap.Windows1252, "Brukernavn=señor\nPassord=blåbær æøå\n")
	got, ok := Decode(input)
	if !ok {
		t.Fatal("expected Windows-1252 input to decode")
	}
	if got != "Brukernavn=señor\nPassord=blåbær æøå\n" {
		t.Fatalf("unexpected Windows-1252 decode result: %q", got)
	}
}

func TestDecodeLatin1(t *testing.T) {
	t.Parallel()

	input := mustEncodeSingleByte(t, charmap.ISO8859_1, "Descripción=niño señor blåbær æøå\n")
	got, ok := Decode(input)
	if !ok {
		t.Fatal("expected Latin-1 input to decode")
	}
	if got != "Descripción=niño señor blåbær æøå\n" {
		t.Fatalf("unexpected Latin-1 decode result: %q", got)
	}
}

func TestLooksLikeTextRecognizesUTF16(t *testing.T) {
	t.Parallel()

	if !LooksLikeText(utf16Bytes("Passord=Vår2026!\n", binary.LittleEndian, true)) {
		t.Fatal("expected UTF-16 text to be treated as text-like")
	}
	if LooksLikeText([]byte{0x00, 0xFF, 0x01, 0x02, 0x03, 0x04}) {
		t.Fatal("expected binary-like sample to stay non-text")
	}
}

func TestLooksLikeTextRejectsValidUTF8BinaryLikeControlBytes(t *testing.T) {
	t.Parallel()

	input := []byte{0x01, 0x02, 0x03, 0x04, 'A', 'B', 'C'}
	if !utf8.Valid(input) {
		t.Fatal("expected sample to be valid UTF-8 for this regression")
	}
	if LooksLikeText(input) {
		t.Fatal("expected valid UTF-8 control-heavy bytes to stay non-text")
	}
	if _, ok := Decode(input); ok {
		t.Fatal("expected valid UTF-8 control-heavy bytes not to decode as text")
	}
}

func utf16Bytes(text string, order binary.ByteOrder, withBOM bool) []byte {
	encoded := utf16.Encode([]rune(text))
	out := make([]byte, 0, len(encoded)*2+2)
	if withBOM {
		if order == binary.LittleEndian {
			out = append(out, 0xFF, 0xFE)
		} else {
			out = append(out, 0xFE, 0xFF)
		}
	}
	buf := make([]byte, 2)
	for _, value := range encoded {
		order.PutUint16(buf, value)
		out = append(out, buf...)
	}
	return out
}

func mustEncodeSingleByte(t *testing.T, encoding *charmap.Charmap, value string) []byte {
	t.Helper()
	out, _, err := transform.Bytes(encoding.NewEncoder(), []byte(value))
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return out
}

// Package legacyoffice extracts visible text from legacy (OLE/CFB) Microsoft
// Office documents: Word 97-2003 (.doc) and Excel 97-2003 (.xls).
//
// The container layer is read with github.com/richardlehane/mscfb (Apache-2.0,
// pure Go). Document text is reconstructed here from the documented on-disk
// structures (Word piece table, Excel BIFF8 records) — no third-party parser
// implementation is copied. Extraction is read-only, bounded, and must fail
// safely on malformed input.
package legacyoffice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/richardlehane/mscfb"
)

// Resource bounds. Legacy parsing must never turn into an unbounded walk.
const (
	MaxContentBytes = 64 << 20
	MaxTextBytes    = 8 << 20
	MaxStreamBytes  = 64 << 20
	MaxPieces       = 8192
	MaxBIFFRecords  = 500000
	MaxSheets       = 128
	MaxCells        = 500000
	MaxCellChars    = 1 << 16
)

var (
	ErrNotLegacyOffice = errors.New("content is not a legacy Office document")
	ErrTooLarge        = errors.New("legacy Office document exceeds the extraction limit")
	ErrUnsupported     = errors.New("legacy Office document type is not supported")
)

// Kind identifies the legacy document family.
type Kind string

const (
	KindWord       Kind = "doc"
	KindExcel      Kind = "xls"
	KindPowerPoint Kind = "ppt"
)

// Status is the stable inspection outcome for a legacy document.
type Status string

const (
	StatusOK          Status = "ok"
	StatusEncrypted   Status = "encrypted"
	StatusUnsupported Status = "unsupported"
	StatusMalformed   Status = "malformed"
	StatusTooLarge    Status = "too_large"
)

// ParserName is the human-readable parser label used in failure reports.
func (k Kind) ParserName() string {
	switch k {
	case KindWord:
		return "legacy Word"
	case KindExcel:
		return "legacy Excel"
	case KindPowerPoint:
		return "legacy PowerPoint"
	default:
		return "legacy Office"
	}
}

// Document is the extracted, non-rendered content of a legacy Office file.
// Text holds reconstructed logical text; table cells are separated by tabs and
// rows by newlines so the shared credential layer can apply the same table
// semantics used for modern Office and delimited exports.
type Document struct {
	Kind        Kind
	Status      Status
	Text        string
	Grid        [][]string
	Encrypted   bool
	Limitations []string
}

// Detail returns the first limitation text, if any.
func (d Document) Detail() string {
	if len(d.Limitations) == 0 {
		return ""
	}
	return d.Limitations[0]
}

var oleSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// IsOLE reports whether the content starts with the OLE compound-file
// signature. Extensions are never trusted on their own.
func IsOLE(content []byte) bool {
	return len(content) >= len(oleSignature) && bytes.Equal(content[:len(oleSignature)], oleSignature)
}

// Extract reads a legacy Office document and returns its visible text.
// ok is false when the content is not a legacy Office document that this
// package handles. Errors are returned only for malformed input.
func Extract(content []byte) (doc Document, ok bool) {
	if !IsOLE(content) {
		return Document{}, false
	}
	if len(content) > MaxContentBytes {
		return Document{Status: StatusTooLarge, Limitations: []string{"document exceeds the legacy extraction size limit"}}, true
	}
	// Defensive: a parser bug on hostile input must degrade to "not inspected"
	// rather than panicking inside a scan worker.
	defer func() {
		if recovered := recover(); recovered != nil {
			doc = Document{Status: StatusMalformed, Limitations: []string{fmt.Sprintf("legacy parser recovered from internal error: %v", recovered)}}
			ok = true
		}
	}()

	streams, err := readStreams(content)
	if err != nil {
		return Document{Status: StatusMalformed, Limitations: []string{fmt.Sprintf("compound file could not be read: %v", err)}}, true
	}

	switch {
	case len(streams["worddocument"]) > 0:
		document, err := extractWord(streams)
		if err != nil {
			return Document{Kind: KindWord, Status: StatusMalformed, Limitations: []string{err.Error()}}, true
		}
		if document.Status == "" {
			document.Status = StatusOK
		}
		return document, true
	case len(streams["workbook"]) > 0 || len(streams["book"]) > 0:
		stream := streams["workbook"]
		if len(stream) == 0 {
			stream = streams["book"]
		}
		document, err := extractBIFF(stream)
		if err != nil {
			return Document{Kind: KindExcel, Status: StatusMalformed, Limitations: []string{err.Error()}}, true
		}
		if document.Status == "" {
			document.Status = StatusOK
		}
		return document, true
	case len(streams["powerpoint document"]) > 0:
		return Document{Kind: KindPowerPoint, Status: StatusUnsupported, Limitations: []string{"PowerPoint 97-2003 text extraction is deferred (record-level slide text parser not implemented)"}}, true
	default:
		return Document{Status: StatusUnsupported, Limitations: []string{ErrUnsupported.Error()}}, true
	}
}

// readStreams reads the streams this package needs, bounded by MaxStreamBytes.
func readStreams(content []byte) (map[string][]byte, error) {
	reader, err := mscfb.New(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("open compound file: %w", err)
	}
	wanted := map[string]bool{
		"worddocument": true, "0table": true, "1table": true,
		"workbook": true, "book": true, "powerpoint document": true,
	}
	streams := make(map[string][]byte, len(wanted))
	for _, entry := range reader.File {
		name := strings.ToLower(strings.TrimSpace(entry.Name))
		if !wanted[name] {
			continue
		}
		if entry.Size < 0 || entry.Size > MaxStreamBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(entry, MaxStreamBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read %s stream: %w", entry.Name, err)
		}
		if len(data) > MaxStreamBytes {
			continue
		}
		streams[name] = data
	}
	return streams, nil
}

// normalizeText converts Word control characters into logical text boundaries:
// table cells become tab separators, rows and paragraphs become newlines.
func normalizeText(text string) string {
	// A table row ends with the cell mark followed by the row mark and the
	// paragraph mark; collapse that sequence to a single row boundary first.
	text = strings.ReplaceAll(text, "\x07\x07\r", "\n")
	text = strings.ReplaceAll(text, "\x07\x07\n", "\n")
	text = strings.ReplaceAll(text, "\x07\x07", "\n") // row end
	text = strings.ReplaceAll(text, "\x07", "\t")     // cell end
	replacements := []struct{ old, new string }{
		{"\r\n", "\n"},
		{"\r", "\n"},
		{"\x0b", "\n"},
		{"\x0c", "\n"},
		{"\x1e", "-"},
		{"\u00a0", " "},
		{"\x13", ""}, // field begin
		{"\x14", ""}, // field separator
		{"\x15", ""}, // field end
		{"\x01", ""}, // picture
		{"\x02", ""}, // footnote reference
		{"\x08", ""}, // drawn object
		{"\x05", ""}, // annotation reference
		{"\x1f", ""}, // optional hyphen
	}
	for _, replacement := range replacements {
		text = strings.ReplaceAll(text, replacement.old, replacement.new)
	}
	var builder strings.Builder
	builder.Grow(len(text))
	for _, r := range text {
		switch {
		case r == '\n' || r == '\t':
			builder.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// drop remaining control characters
		default:
			builder.WriteRune(r)
		}
	}
	return trimLongText(builder.String())
}

func trimLongText(text string) string {
	if len(text) <= MaxTextBytes {
		return text
	}
	return text[:MaxTextBytes]
}

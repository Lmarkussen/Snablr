// Package officefixture builds real (minimal but valid) OOXML documents for
// regression fixtures and tests. Packages are assembled with the required
// content types, relationships, and parts so they are genuine DOCX/XLSX/PPTX
// containers rather than text files with an Office extension.
package officefixture

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sort"
	"strings"
)

const (
	WNS = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	ANS = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"`
	PNS = `xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"`
	RNS = `xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`
)

func DOCX(body ...string) []byte {
	return DOCXWithParts(nil, body...)
}

// DOCXWithParts builds a DOCX and merges additional Word parts into the
// package. Tests use it to place text in secondary Word parts such as
// word/footnotes.xml, word/comments.xml, or word/diagrams/data1.xml.
func DOCXWithParts(extra map[string]string, body ...string) []byte {
	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document ` + WNS + `><w:body>` + strings.Join(body, "") +
		`<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr></w:body></w:document>`
	parts := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`,
		"word/document.xml": document,
	}
	for name, part := range extra {
		parts[name] = part
	}
	return ZIPBytes(parts)
}

func Paragraph(text string) string {
	return `<w:p><w:r><w:t xml:space="preserve">` + xmlEscape(text) + `</w:t></w:r></w:p>`
}

func RunParagraph(runs ...string) string {
	var builder strings.Builder
	builder.WriteString(`<w:p>`)
	for _, run := range runs {
		builder.WriteString(`<w:r><w:t xml:space="preserve">` + xmlEscape(run) + `</w:t></w:r>`)
	}
	builder.WriteString(`</w:p>`)
	return builder.String()
}

func Table(rows ...[]string) string {
	var builder strings.Builder
	builder.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>`)
	for _, row := range rows {
		builder.WriteString(`<w:tr>`)
		for _, cell := range row {
			builder.WriteString(`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/></w:tcPr>` + Paragraph(cell) + `</w:tc>`)
		}
		builder.WriteString(`</w:tr>`)
	}
	builder.WriteString(`</w:tbl>`)
	return builder.String()
}

// TableCell describes one Word table cell for fixtures that need more than a
// single plain paragraph: split runs, multiple paragraphs, blank cells, or a
// horizontal merge.
type TableCell struct {
	// Paragraphs renders one paragraph per entry (an empty entry is a blank
	// paragraph, which terminates a logical block).
	Paragraphs []string
	// Runs, when set, renders one paragraph whose runs are concatenated without
	// separators, modelling a word split by Word's run boundaries.
	Runs [][]string
	// GridSpan marks a horizontal merge across N columns (0 or 1 means none).
	GridSpan int
}

// TableXML renders a Word table from explicit cell definitions so tests can
// model real-world header-row credential tables.
func TableXML(rows ...[]TableCell) string {
	var builder strings.Builder
	builder.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr>`)
	for _, row := range rows {
		builder.WriteString(`<w:tr>`)
		for _, cell := range row {
			builder.WriteString(`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/>`)
			if cell.GridSpan > 1 {
				builder.WriteString(fmt.Sprintf(`<w:gridSpan w:val="%d"/>`, cell.GridSpan))
			}
			builder.WriteString(`</w:tcPr>`)
			switch {
			case len(cell.Runs) > 0:
				builder.WriteString(`<w:p>`)
				for _, run := range cell.Runs {
					if len(run) == 0 {
						builder.WriteString(Paragraph(""))
						continue
					}
					builder.WriteString(`<w:r>`)
					for _, part := range run {
						builder.WriteString(`<w:t xml:space="preserve">` + xmlEscape(part) + `</w:t>`)
					}
					builder.WriteString(`</w:r>`)
				}
				builder.WriteString(`</w:p>`)
			case len(cell.Paragraphs) > 0:
				for _, paragraph := range cell.Paragraphs {
					builder.WriteString(Paragraph(paragraph))
				}
			default:
				builder.WriteString(Paragraph(""))
			}
			builder.WriteString(`</w:tc>`)
		}
		builder.WriteString(`</w:tr>`)
	}
	builder.WriteString(`</w:tbl>`)
	return builder.String()
}

// Cell builds a plain single-paragraph table cell.
func Cell(text string) TableCell {
	return TableCell{Paragraphs: []string{text}}
}

// SplitCell builds a cell whose visible text is split across Word runs.
func SplitCell(parts ...string) TableCell {
	return TableCell{Runs: [][]string{parts}}
}

// ParaCell builds a cell holding several paragraphs.
func ParaCell(paragraphs ...string) TableCell {
	return TableCell{Paragraphs: paragraphs}
}

// MergedCell builds a horizontally merged cell spanning columns.
func MergedCell(span int, text string) TableCell {
	return TableCell{Paragraphs: []string{text}, GridSpan: span}
}

func XLSX(rows [][]string) []byte {
	return XLSXWithParts(nil, rows, false)
}

// XLSXInline builds a spreadsheet that stores cell text inline (t="inlineStr")
// instead of through the shared string table, which is what several exporters
// and "save as" paths produce.
func XLSXInline(rows [][]string) []byte {
	return XLSXWithParts(nil, rows, true)
}

// XLSXWithParts builds a spreadsheet and merges additional parts such as
// xl/comments1.xml or xl/drawings/drawing1.xml.
func XLSXWithParts(extra map[string]string, rows [][]string, inline bool) []byte {
	var shared []string
	index := map[string]int{}
	if !inline {
		for _, row := range rows {
			for _, cell := range row {
				if _, ok := index[cell]; !ok {
					index[cell] = len(shared)
					shared = append(shared, cell)
				}
			}
		}
	}
	var sheet strings.Builder
	sheet.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sheet.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for rowIndex, row := range rows {
		sheet.WriteString(fmt.Sprintf(`<row r="%d">`, rowIndex+1))
		for columnIndex, cell := range row {
			reference := columnName(columnIndex) + fmt.Sprintf("%d", rowIndex+1)
			if inline {
				sheet.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, reference, xmlEscape(cell)))
				continue
			}
			sheet.WriteString(fmt.Sprintf(`<c r="%s" t="s"><v>%d</v></c>`, reference, index[cell]))
		}
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	var sst strings.Builder
	sst.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	sst.WriteString(fmt.Sprintf(`<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" uniqueCount="%d">`, len(shared), len(shared)))
	for _, value := range shared {
		sst.WriteString(`<si><t xml:space="preserve">` + xmlEscape(value) + `</t></si>`)
	}
	sst.WriteString(`</sst>`)

	parts := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
			`<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
			`</Relationships>`,
		"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<workbook ` + RNS + `><sheets><sheet name="Ark1" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>` +
			`</Relationships>`,
		"xl/sharedStrings.xml":     sst.String(),
		"xl/worksheets/sheet1.xml": sheet.String(),
	}
	for name, part := range extra {
		parts[name] = part
	}
	return ZIPBytes(parts)
}

func PPTX(paragraphs []string) []byte {
	var body strings.Builder
	for _, text := range paragraphs {
		body.WriteString(`<a:p><a:r><a:t>` + xmlEscape(text) + `</a:t></a:r></a:p>`)
	}
	slide := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<p:sld ` + ANS + ` ` + PNS + ` ` + RNS + `><p:cSld><p:spTree>` +
		`<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>` +
		`<p:sp><p:nvSpPr><p:cNvPr id="2" name="TextBox 1"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr/>` +
		`<p:txBody><a:bodyPr/>` + body.String() + `</p:txBody></p:sp>` +
		`</p:spTree></p:cSld></p:sld>`
	return ZIPBytes(map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>` +
			`<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>` +
			`</Relationships>`,
		"ppt/presentation.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<p:presentation ` + PNS + ` ` + RNS + `><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>`,
		"ppt/_rels/presentation.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>` +
			`</Relationships>`,
		"ppt/slides/slide1.xml": slide,
	})
}

func ZIPBytes(members map[string]string) []byte {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	// Deterministic order for reproducible fixtures: the well-known parts keep
	// their historical order (so existing fixtures stay byte-identical), then
	// any additional part is appended in sorted order.
	written := make(map[string]struct{}, len(members))
	names := make([]string, 0, len(members))
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml", "ppt/presentation.xml", "ppt/_rels/presentation.xml.rels", "ppt/slides/slide1.xml", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/sharedStrings.xml", "xl/worksheets/sheet1.xml", "passordliste.docx"} {
		if _, ok := members[name]; !ok {
			continue
		}
		names = append(names, name)
		written[name] = struct{}{}
	}
	extra := make([]string, 0, len(members))
	for name := range members {
		if _, ok := written[name]; ok {
			continue
		}
		extra = append(extra, name)
	}
	sort.Strings(extra)
	names = append(names, extra...)
	for _, name := range names {
		content := members[name]
		fileWriter, err := writer.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := fileWriter.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func columnName(index int) string {
	name := ""
	index++
	for index > 0 {
		index--
		name = string(rune('A'+index%26)) + name
		index /= 26
	}
	return name
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

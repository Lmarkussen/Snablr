package archiveinspect

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"snablr/internal/credentialanalysis"
)

// OOXML text reconstruction.
//
// Office parts store human text as many small XML runs. A visually continuous
// word such as "Passord" may be split across several runs because of
// formatting, spell-check, or language changes:
//
//	<w:r><w:t>Pass</w:t></w:r><w:r><w:t>ord</w:t></w:r>
//
// Extracting each run as an independent line destroys the logical word and
// defeats credential matching. This file reconstructs logical text before
// harvesting while preserving useful boundaries (paragraph, table row, slide
// text box, worksheet row).
//
// Structure only: no credential vocabulary lives here. Which labels denote an
// identity, password, or domain field is decided by the shared
// credentialanalysis semantic layer.

const (
	maxBodyBlockLines = 12
	maxReconstructed  = 8 << 20
)

type officeContext struct {
	sharedStrings []string
}

// reconstructOfficeMember returns the reconstructed text for one OOXML part.
// It returns nil when the part carries no reconstructable human text.
func reconstructOfficeMember(outerExtension, memberPath string, raw []byte, ctx *officeContext) []byte {
	memberPath = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(memberPath, `\`, "/")))
	switch {
	case strings.HasSuffix(memberPath, "custom.xml"):
		if text := reconstructCustomProperties(raw); text != "" {
			return []byte(text)
		}
	case outerExtension == ".docx" && strings.HasSuffix(memberPath, ".xml"):
		if text := reconstructWordDocument(raw); text != "" {
			return []byte(text)
		}
	case isSpreadsheetExtension(outerExtension) && memberPath == "xl/sharedstrings.xml":
		if text := reconstructSharedStringsText(raw); text != "" {
			return []byte(text)
		}
	case isSpreadsheetExtension(outerExtension) && strings.HasPrefix(memberPath, "xl/worksheets/"):
		if text := reconstructWorksheet(raw, ctx); text != "" {
			return []byte(text)
		}
	case isSpreadsheetExtension(outerExtension) && strings.HasPrefix(memberPath, "xl/comments"):
		if text := reconstructSpreadsheetComments(raw); text != "" {
			return []byte(text)
		}
	case isSpreadsheetExtension(outerExtension) && strings.HasPrefix(memberPath, "xl/threadedcomments/"):
		if text := reconstructSpreadsheetComments(raw); text != "" {
			return []byte(text)
		}
	case isSpreadsheetExtension(outerExtension) && strings.HasPrefix(memberPath, "xl/drawings/"):
		if text := reconstructParagraphBlocks(raw, "excel drawing"); text != "" {
			return []byte(text)
		}
	case outerExtension == ".pptx" && strings.HasPrefix(memberPath, "ppt/slides/"):
		if text := reconstructSlide(raw); text != "" {
			return []byte(text)
		}
	}
	return nil
}

// isSpreadsheetExtension covers the OOXML spreadsheet family that shares the
// xl/ part layout (workbook, worksheets, shared strings).
func isSpreadsheetExtension(extension string) bool {
	switch extension {
	case ".xlsx", ".xlsm":
		return true
	default:
		return false
	}
}

// ---------- WordprocessingML ----------

type wordItem struct {
	paragraph string
	grid      [][]string
	isTable   bool
}

func reconstructWordDocument(raw []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset

	var (
		items       []wordItem
		tableStack  [][][]string
		currentRow  []string
		currentCell strings.Builder
		paragraph   strings.Builder
		inCell      bool
		inTable     bool
		inParagraph bool
	)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Malformed XML: keep whatever was reconstructed so far.
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "tbl":
				inTable = true
				tableStack = append(tableStack, nil)
			case "tr":
				if inTable {
					currentRow = nil
				}
			case "tc":
				if inTable {
					inCell = true
					currentCell.Reset()
				}
			case "p":
				inParagraph = true
				paragraph.Reset()
			case "t":
				// handled on CharData
			case "tab":
				if inCell {
					currentCell.WriteString("\t")
				} else if inParagraph {
					paragraph.WriteString("\t")
				}
			case "br", "cr":
				if inCell {
					currentCell.WriteString("\n")
				} else if inParagraph {
					paragraph.WriteString("\n")
				}
			}
		case xml.CharData:
			text := string(element)
			if inCell {
				currentCell.WriteString(text)
			} else if inParagraph {
				paragraph.WriteString(text)
			}
		case xml.EndElement:
			switch element.Name.Local {
			case "p":
				inParagraph = false
				text := paragraph.String()
				paragraph.Reset()
				if inCell {
					if strings.TrimSpace(text) != "" {
						if currentCell.Len() > 0 {
							currentCell.WriteString(" ")
						}
						currentCell.WriteString(text)
					}
					break
				}
				items = append(items, wordItem{paragraph: text})
			case "tc":
				if inCell {
					currentRow = append(currentRow, currentCell.String())
					currentCell.Reset()
					inCell = false
				}
			case "tr":
				if inTable && len(currentRow) > 0 {
					tableStack[len(tableStack)-1] = append(tableStack[len(tableStack)-1], currentRow)
					currentRow = nil
				}
			case "tbl":
				if len(tableStack) > 0 {
					grid := tableStack[len(tableStack)-1]
					tableStack = tableStack[:len(tableStack)-1]
					if len(tableStack) == 0 {
						inTable = false
					}
					items = append(items, wordItem{grid: grid, isTable: true})
				}
			}
		}
	}
	return renderWordItems(items)
}

func renderWordItems(items []wordItem) string {
	var builder strings.Builder
	var block []string
	blockIndex := 0
	tableIndex := 0

	flushBlock := func() {
		lines := pairAdjacentLabels(block)
		block = nil
		if len(lines) == 0 {
			return
		}
		blockIndex++
		builder.WriteString(fmt.Sprintf("[word body block %d]\n", blockIndex))
		for _, line := range lines {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}

	for _, item := range items {
		if item.isTable {
			flushBlock()
			if rendered := credentialanalysis.RenderTableText(item.grid, "word table"); rendered != "" {
				tableIndex++
				builder.WriteString(rendered)
			}
			continue
		}
		text := strings.TrimSpace(item.paragraph)
		if text == "" {
			flushBlock()
			continue
		}
		for _, line := range splitParagraphLines(item.paragraph) {
			if strings.TrimSpace(line) == "" {
				continue
			}
			block = append(block, line)
			if len(block) >= maxBodyBlockLines {
				flushBlock()
			}
		}
	}
	flushBlock()
	return truncateText(builder.String())
}

func splitParagraphLines(paragraph string) []string {
	paragraph = strings.ReplaceAll(paragraph, "\r\n", "\n")
	paragraph = strings.ReplaceAll(paragraph, "\r", "\n")
	return strings.Split(paragraph, "\n")
}

// reconstructParagraphBlocks reconstructs paragraph text from a non-body part,
// such as a spreadsheet DrawingML text box. WordprocessingML (w:p/w:t) and
// DrawingML (a:p/a:t) share the same local element names, so one walker covers
// both. Text is emitted as bounded logical blocks so labels and values inside
// one text box correlate without merging unrelated shapes.
func reconstructParagraphBlocks(raw []byte, scope string) string {
	return renderParagraphBlocks(parseParagraphTexts(raw), scope)
}

// parseParagraphTexts collects the text of every paragraph element. Runs inside
// a paragraph are concatenated without a separator so words split across runs
// survive; "br" elements become line breaks.
func parseParagraphTexts(raw []byte) []string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset
	var (
		paragraphs []string
		current    strings.Builder
		inBlock    bool
	)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "p":
				inBlock = true
				current.Reset()
			case "br":
				if inBlock {
					current.WriteString("\n")
				}
			}
		case xml.CharData:
			if inBlock {
				current.WriteString(string(element))
			}
		case xml.EndElement:
			if element.Name.Local == "p" && inBlock {
				paragraphs = append(paragraphs, current.String())
				current.Reset()
				inBlock = false
			}
		}
	}
	return paragraphs
}

// renderParagraphBlocks renders paragraph text as bounded [scope block N]
// sections with adjacency pairing applied.
func renderParagraphBlocks(paragraphs []string, scope string) string {
	var builder strings.Builder
	var block []string
	index := 0
	flush := func() {
		lines := pairAdjacentLabels(block)
		block = nil
		if len(lines) == 0 {
			return
		}
		index++
		builder.WriteString(fmt.Sprintf("[%s block %d]\n", scope, index))
		for _, line := range lines {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}
	for _, paragraph := range paragraphs {
		if strings.TrimSpace(paragraph) == "" {
			flush()
			continue
		}
		for _, line := range splitParagraphLines(paragraph) {
			if strings.TrimSpace(line) == "" {
				continue
			}
			block = append(block, line)
			if len(block) >= maxBodyBlockLines {
				flush()
			}
		}
	}
	flush()
	return truncateText(builder.String())
}

// reconstructSpreadsheetComments reconstructs Excel cell comments (legacy
// comments1.xml and threaded comments). Each comment becomes its own record so a
// label/value pair written in a note correlates with that note only.
func reconstructSpreadsheetComments(raw []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset
	var (
		comments []string
		current  strings.Builder
		inNote   bool
	)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "comment", "threadedComment":
				inNote = true
				current.Reset()
			case "br":
				if inNote {
					current.WriteString("\n")
				}
			}
		case xml.CharData:
			if inNote {
				current.WriteString(string(element))
			}
		case xml.EndElement:
			if (element.Name.Local == "comment" || element.Name.Local == "threadedComment") && inNote {
				comments = append(comments, current.String())
				current.Reset()
				inNote = false
			}
		}
	}
	if len(comments) == 0 {
		return ""
	}
	var builder strings.Builder
	index := 0
	for _, comment := range comments {
		var lines []string
		for _, line := range splitParagraphLines(comment) {
			if strings.TrimSpace(line) != "" {
				lines = append(lines, line)
			}
		}
		lines = pairAdjacentLabels(lines)
		if len(lines) == 0 {
			continue
		}
		index++
		builder.WriteString(fmt.Sprintf("[excel comment %d]\n", index))
		for _, line := range lines {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}
	return truncateText(builder.String())
}

// pairAdjacentLabels joins a bare label line with the value line that
// immediately follows it, which is how label and value are laid out when a
// document puts them on separate paragraphs. The decision about what counts as
// a label comes from the shared semantic classifier.
func pairAdjacentLabels(lines []string) []string {
	paired := make([]string, 0, len(lines))
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		if isBareLabel(line) && index+1 < len(lines) {
			next := strings.TrimSpace(lines[index+1])
			if next != "" && !isBareLabel(next) && !hasAssignment(next) {
				paired = append(paired, line+"="+next)
				index++
				continue
			}
		}
		paired = append(paired, line)
	}
	return paired
}

func isBareLabel(line string) bool {
	if hasAssignment(line) || len([]rune(line)) > 32 {
		return false
	}
	return credentialanalysis.ClassifyFieldName(line) != credentialanalysis.FieldRoleNone
}

func hasAssignment(line string) bool {
	return strings.ContainsAny(line, "=:")
}

// ---------- SpreadsheetML ----------

func reconstructSharedStringsText(raw []byte) string {
	values := parseSharedStrings(raw)
	if len(values) == 0 {
		return ""
	}
	// Keep the artifact recognizable: indexed shared strings are also emitted
	// as plain lines so connection strings and assignments survive unchanged.
	var builder strings.Builder
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		builder.WriteString(value)
		builder.WriteString("\n")
	}
	return truncateText(builder.String())
}

func parseSharedStrings(raw []byte) []string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset
	var (
		values  []string
		current strings.Builder
		inSI    bool
	)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "si":
				inSI = true
				current.Reset()
			}
		case xml.CharData:
			if inSI {
				current.WriteString(string(element))
			}
		case xml.EndElement:
			if element.Name.Local == "si" && inSI {
				values = append(values, current.String())
				current.Reset()
				inSI = false
			}
		}
	}
	return values
}

func reconstructWorksheet(raw []byte, ctx *officeContext) string {
	grid := parseWorksheetGrid(raw, ctx)
	if len(grid) == 0 {
		return ""
	}
	if rendered := credentialanalysis.RenderTableText(grid, "worksheet"); rendered != "" {
		return truncateText(rendered)
	}
	// Not a recognized credential table: keep the extracted cells as plain
	// lines so ordinary assignments and connection strings still surface.
	var builder strings.Builder
	for _, row := range grid {
		line := strings.Join(row, " ")
		line = strings.TrimSpace(strings.Join(strings.Fields(line), " "))
		if line == "" {
			continue
		}
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return truncateText(builder.String())
}

func parseWorksheetGrid(raw []byte, ctx *officeContext) [][]string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset

	var (
		grid           [][]string
		currentRow     []string
		currentColumn  int
		inRow          bool
		inCell         bool
		cellType       string
		cellValue      strings.Builder
		inlineValue    strings.Builder
		inInlineString bool
	)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "row":
				inRow = true
				currentRow = nil
			case "c":
				inCell = true
				cellType = ""
				cellValue.Reset()
				currentColumn = -1
				for _, attr := range element.Attr {
					switch attr.Name.Local {
					case "t":
						cellType = strings.ToLower(strings.TrimSpace(attr.Value))
					case "r":
						if index, ok := columnIndex(attr.Value); ok {
							currentColumn = index
						}
					}
				}
			case "is":
				if inCell {
					inInlineString = true
					inlineValue.Reset()
				}
			}
		case xml.CharData:
			if inCell && !inInlineString {
				cellValue.WriteString(string(element))
			}
			if inInlineString {
				inlineValue.WriteString(string(element))
			}
		case xml.EndElement:
			switch element.Name.Local {
			case "is":
				inInlineString = false
			case "c":
				if inCell {
					value := resolveCellValue(cellType, cellValue.String(), inlineValue.String(), ctx)
					switch {
					case currentColumn < 0:
						currentRow = append(currentRow, value)
					case len(currentRow) > currentColumn:
						currentRow[currentColumn] = value
					default:
						for len(currentRow) < currentColumn {
							currentRow = append(currentRow, "")
						}
						currentRow = append(currentRow, value)
					}
					inCell = false
				}
			case "row":
				if inRow {
					grid = append(grid, currentRow)
					currentRow = nil
					inRow = false
				}
			}
		}
	}
	// Drop fully empty trailing rows.
	for len(grid) > 0 && rowEmpty(grid[len(grid)-1]) {
		grid = grid[:len(grid)-1]
	}
	return grid
}

func resolveCellValue(cellType, rawValue, inlineValue string, ctx *officeContext) string {
	rawValue = strings.TrimSpace(rawValue)
	switch cellType {
	case "s":
		index, err := strconv.Atoi(rawValue)
		if err != nil || ctx == nil || index < 0 || index >= len(ctx.sharedStrings) {
			return ""
		}
		return ctx.sharedStrings[index]
	case "inlineStr":
		return inlineValue
	case "str", "e", "b", "n":
		return rawValue
	default:
		if rawValue == "" {
			return inlineValue
		}
		return rawValue
	}
}

func columnIndex(reference string) (int, bool) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return 0, false
	}
	index := 0
	letters := 0
	for _, r := range reference {
		switch {
		case r >= 'A' && r <= 'Z':
			index = index*26 + int(r-'A'+1)
			letters++
		case r >= 'a' && r <= 'z':
			index = index*26 + int(r-'a'+1)
			letters++
		default:
			if letters == 0 {
				return 0, false
			}
			return index - 1, true
		}
	}
	if letters == 0 {
		return 0, false
	}
	return index - 1, true
}

// ---------- PresentationML ----------

func reconstructSlide(raw []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset

	var (
		builder     strings.Builder
		shapeLines  []string
		tableStack  [][][]string
		currentRow  []string
		currentCell strings.Builder
		paragraph   strings.Builder
		inShape     bool
		inTable     bool
		inCell      bool
		inParagraph bool
		shapeIndex  int
	)

	flushShape := func() {
		if len(shapeLines) == 0 {
			return
		}
		shapeIndex++
		builder.WriteString(fmt.Sprintf("[slide text box %d]\n", shapeIndex))
		for _, line := range pairAdjacentLabels(shapeLines) {
			builder.WriteString(line)
			builder.WriteString("\n")
		}
		shapeLines = nil
	}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "sp", "graphicFrame":
				if !inShape {
					inShape = true
					shapeLines = nil
				}
			case "tbl":
				inTable = true
				tableStack = append(tableStack, nil)
			case "tr":
				if inTable {
					currentRow = nil
				}
			case "tc":
				if inTable {
					inCell = true
					currentCell.Reset()
				}
			case "p":
				inParagraph = true
				paragraph.Reset()
			case "br":
				if inParagraph {
					paragraph.WriteString("\n")
				}
			}
		case xml.CharData:
			if inCell {
				currentCell.WriteString(string(element))
			} else if inParagraph {
				paragraph.WriteString(string(element))
			}
		case xml.EndElement:
			switch element.Name.Local {
			case "p":
				if inParagraph {
					text := strings.TrimSpace(paragraph.String())
					paragraph.Reset()
					inParagraph = false
					if text == "" {
						break
					}
					if inCell {
						if currentCell.Len() > 0 {
							currentCell.WriteString(" ")
						}
						currentCell.WriteString(text)
						break
					}
					shapeLines = append(shapeLines, text)
				}
			case "tc":
				if inCell {
					currentRow = append(currentRow, currentCell.String())
					currentCell.Reset()
					inCell = false
				}
			case "tr":
				if inTable && len(currentRow) > 0 {
					tableStack[len(tableStack)-1] = append(tableStack[len(tableStack)-1], currentRow)
					currentRow = nil
				}
			case "tbl":
				if len(tableStack) > 0 {
					grid := tableStack[len(tableStack)-1]
					tableStack = tableStack[:len(tableStack)-1]
					if len(tableStack) == 0 {
						inTable = false
					}
					if rendered := credentialanalysis.RenderTableText(grid, "slide table"); rendered != "" {
						builder.WriteString(rendered)
					}
				}
			case "sp", "graphicFrame":
				if inShape {
					flushShape()
					inShape = false
				}
			}
		}
	}
	flushShape()
	return truncateText(builder.String())
}

// ---------- Custom document properties ----------

func reconstructCustomProperties(raw []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.CharsetReader = passThroughCharset
	var (
		lines  []string
		name   string
		value  strings.Builder
		inProp bool
	)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local == "property" {
				inProp = true
				name = ""
				value.Reset()
				for _, attr := range element.Attr {
					if attr.Name.Local == "name" {
						name = strings.TrimSpace(attr.Value)
					}
				}
			}
		case xml.CharData:
			if inProp {
				value.WriteString(string(element))
			}
		case xml.EndElement:
			if element.Name.Local == "property" && inProp {
				if name != "" && strings.TrimSpace(value.String()) != "" {
					lines = append(lines, name+"="+strings.TrimSpace(value.String()))
				}
				name = ""
				value.Reset()
				inProp = false
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("[custom document properties]\n")
	for _, line := range lines {
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return truncateText(builder.String())
}

func rowEmpty(row []string) bool {
	for _, cell := range row {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

func truncateText(text string) string {
	if len(text) > maxReconstructed {
		return text[:maxReconstructed]
	}
	return text
}

// passThroughCharset keeps the XML decoder tolerant of declared charsets; the
// part bytes are already decoded to UTF-8 by the caller's text pipeline.
func passThroughCharset(_ string, input io.Reader) (io.Reader, error) {
	return input, nil
}

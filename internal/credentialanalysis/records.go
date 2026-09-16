package credentialanalysis

import (
	"encoding/csv"
	"strconv"
	"strings"
	"unicode"
)

// Tabular record handling shared by every source that can produce rows of
// credential fields: Office documents, spreadsheets, and CSV/TSV exports.
//
// Adapters supply structure only (rows of cells). All language semantics stay
// in this package: the classifier decides which header cells denote an
// identity, password, or domain field, and the harvester decides how records
// are correlated. No adapter may introduce its own credential vocabulary.

const (
	maxRenderedRecords = 512
	headerSearchDepth  = 10
)

// RenderTableText renders tabular rows into the harvester's sectioned field
// text. Each emitted record is its own [scope record N] section so that fields
// are correlated only inside one record and can never pair across rows.
//
// It returns "" when the table cannot be interpreted as credential records, so
// callers can fall back to plain text harvesting.
func RenderTableText(rows [][]string, scope string) string {
	grid := normalizeGrid(rows)
	if len(grid) == 0 {
		return ""
	}
	width := gridWidth(grid)
	if width < 2 {
		return ""
	}
	scope = sanitizeScope(scope)
	if scope == "" {
		scope = "record"
	}

	for i := 0; i < len(grid) && i < headerSearchDepth; i++ {
		if !isCredentialHeaderRow(grid[i]) {
			continue
		}
		return renderHeaderRecords(grid[i], grid[i+1:], width, scope)
	}
	if width == 2 {
		return renderLabelValueRecords(grid, scope)
	}
	return ""
}

// renderHeaderRecords maps each data row onto the header row, one section per
// row. Row boundaries are hard boundaries: row 1 can never pair with row 2.
func renderHeaderRecords(header []string, data [][]string, width int, scope string) string {
	var builder strings.Builder
	records := 0
	for _, row := range data {
		if records >= maxRenderedRecords {
			break
		}
		// Word repeats header rows across page breaks; a repeated header
		// reaffirms the schema and is never a data credential.
		if repeatsHeaderSchema(header, row) {
			continue
		}
		fields := make([]string, 0, width)
		for column := 0; column < width; column++ {
			line, ok := renderField(cellAt(header, column), cellAt(row, column))
			if ok {
				fields = append(fields, line)
			}
		}
		if len(fields) == 0 {
			continue
		}
		records++
		writeRecord(&builder, scope, records, fields)
	}
	if records == 0 {
		return ""
	}
	return builder.String()
}

// renderLabelValueRecords treats a two-column table as label/value pairs. Rows
// accumulate into one record until a label repeats, at which point a new record
// starts; this keeps multi-account label/value lists from mixing accounts.
func renderLabelValueRecords(grid [][]string, scope string) string {
	// A label/value table is only a credential table when its labels name both a
	// password and an identity. Documentation tables such as
	// "Passord | Kommentar" or "Policy | Password" must not become credentials.
	if !hasCredentialLabelPair(grid) {
		return ""
	}
	var (
		builder strings.Builder
		current []string
		seen    = map[string]struct{}{}
		records = 0
	)
	flush := func() {
		if len(current) == 0 {
			return
		}
		records++
		writeRecord(&builder, scope, records, current)
		current = nil
		seen = map[string]struct{}{}
	}
	for _, row := range grid {
		if records >= maxRenderedRecords {
			break
		}
		line, ok := renderField(cellAt(row, 0), cellAt(row, 1))
		if !ok {
			continue
		}
		key := strings.ToLower(strings.SplitN(line, "=", 2)[0])
		if _, duplicate := seen[key]; duplicate {
			flush()
		}
		seen[key] = struct{}{}
		current = append(current, line)
	}
	flush()
	if records == 0 {
		return ""
	}
	return builder.String()
}

func writeRecord(builder *strings.Builder, scope string, index int, fields []string) {
	builder.WriteString("[")
	builder.WriteString(scope)
	builder.WriteString(" record ")
	builder.WriteString(strconv.Itoa(index))
	builder.WriteString("]\n")
	for _, field := range fields {
		builder.WriteString(field)
		builder.WriteString("\n")
	}
}

// renderField emits one "key=value" assignment line. Values containing the
// comment characters the assignment parser stops at are quoted instead.
func renderField(key, value string) (string, bool) {
	key = sanitizeFieldKey(key)
	value = normalizeFieldValue(value)
	if key == "" || value == "" {
		return "", false
	}
	if strings.ContainsAny(value, "#;") {
		if strings.ContainsAny(value, `"'`) {
			return "", false
		}
		return key + `="` + value + `"`, true
	}
	if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, `'`) {
		return "", false
	}
	return key + "=" + value, true
}

// ParseDelimitedText parses comma-, semicolon-, or tab-separated text into rows
// when the delimiter use is consistent across the leading lines.
func ParseDelimitedText(text string) ([][]string, bool) {
	delimiter, ok := detectDelimiter(text)
	if !ok {
		return nil, false
	}
	reader := csv.NewReader(strings.NewReader(text))
	reader.Comma = delimiter
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	var rows [][]string
	for len(rows) < 4096 {
		record, err := reader.Read()
		if err != nil {
			break
		}
		rows = append(rows, record)
	}
	if len(rows) < 2 {
		return nil, false
	}
	return rows, true
}

func detectDelimiter(text string) (rune, bool) {
	lines := leadingNonEmptyLines(text, 10)
	if len(lines) < 2 {
		return 0, false
	}
	best := rune(0)
	bestScore := 0
	for _, candidate := range []rune{',', '\t', ';'} {
		minimum := -1
		maximum := 0
		for _, line := range lines {
			count := strings.Count(line, string(candidate))
			if minimum < 0 || count < minimum {
				minimum = count
			}
			if count > maximum {
				maximum = count
			}
		}
		if minimum < 1 || maximum > minimum+1 {
			continue
		}
		if minimum > bestScore {
			bestScore = minimum
			best = candidate
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

func leadingNonEmptyLines(text string, limit int) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

// isCredentialHeaderRow reports whether a row defines a credential schema:
// at least one password column plus at least one identity column. Unrelated
// columns (server names, free-text comments) are allowed and ignored, which is
// what real password lists with extra columns look like.
func isCredentialHeaderRow(row []string) bool {
	passwords, identities := 0, 0
	for _, cell := range row {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			continue
		}
		switch ClassifyFieldName(cell) {
		case FieldRolePassword:
			passwords++
		case FieldRoleIdentity:
			identities++
		}
	}
	return passwords >= 1 && identities >= 1
}

// repeatsHeaderSchema reports whether a data row is actually a repeated header
// row: every non-empty cell names the same semantic role as the header cell in
// the same column, and the row defines a credential schema itself.
func repeatsHeaderSchema(header, row []string) bool {
	if !isCredentialHeaderRow(row) {
		return false
	}
	for index, cell := range row {
		cell = strings.TrimSpace(cell)
		if cell == "" {
			continue
		}
		if len(header) <= index {
			return false
		}
		if ClassifyFieldName(cell) != ClassifyFieldName(header[index]) {
			return false
		}
	}
	return true
}

// hasCredentialLabelPair reports whether the first column of a two-column table
// labels both a password and an identity somewhere in the table.
func hasCredentialLabelPair(grid [][]string) bool {
	passwords, identities := 0, 0
	for _, row := range grid {
		switch ClassifyFieldName(cellAt(row, 0)) {
		case FieldRolePassword:
			passwords++
		case FieldRoleIdentity:
			identities++
		}
	}
	return passwords >= 1 && identities >= 1
}

func normalizeGrid(rows [][]string) [][]string {
	grid := make([][]string, 0, len(rows))
	for _, row := range rows {
		cells := make([]string, 0, len(row))
		empty := true
		for _, cell := range row {
			cell = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(cell, "\r\n", " "), "\n", " "))
			cells = append(cells, cell)
			if cell != "" {
				empty = false
			}
		}
		if empty {
			continue
		}
		grid = append(grid, cells)
	}
	return grid
}

func gridWidth(grid [][]string) int {
	width := 0
	for _, row := range grid {
		if len(row) > width {
			width = len(row)
		}
	}
	return width
}

func cellAt(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return row[index]
}

func normalizeFieldValue(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	return strings.TrimSpace(value)
}

// sanitizeFieldKey reduces a human label to the key alphabet the assignment
// parser accepts. Norwegian letters are transliterated so labels such as
// "Pålogging" survive as "palogging".
func sanitizeFieldKey(key string) string {
	var builder strings.Builder
	underscore := false
	for _, r := range key {
		switch r {
		case 'æ', 'Æ':
			builder.WriteString("ae")
			underscore = false
			continue
		case 'ø', 'Ø':
			builder.WriteString("o")
			underscore = false
			continue
		case 'å', 'Å':
			builder.WriteString("a")
			underscore = false
			continue
		}
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			underscore = false
		case r == '.' || r == '-' || r == '_' || r == ' ' || r == '\t':
			if !underscore && builder.Len() > 0 {
				builder.WriteByte('_')
				underscore = true
			}
		}
	}
	return strings.Trim(builder.String(), "_")
}

func sanitizeScope(scope string) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scope = sanitizeFieldKey(scope)
	scope = strings.ReplaceAll(scope, "_", " ")
	return strings.TrimSpace(scope)
}

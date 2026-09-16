package legacyoffice

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/encoding/charmap"
)

// Excel BIFF8 record types used for bounded, read-only cell recovery.
const (
	biffRecordBOF        = 0x0809
	biffRecordEOF        = 0x000A
	biffRecordFilePass   = 0x002F
	biffRecordBoundSheet = 0x0085
	biffRecordSST        = 0x00FC
	biffRecordContinue   = 0x003C
	biffRecordLabelSST   = 0x00FD
	biffRecordLabel      = 0x0204
	biffRecordRK         = 0x027E
	biffRecordMulRK      = 0x00BD
	biffRecordNumber     = 0x0203
	biffRecordBoolErr    = 0x0205
	biffRecordFormula    = 0x0006
	biffRecordString     = 0x0207
)

// extractBIFF reconstructs a cell grid from the BIFF8 workbook stream. The grid
// is handed to the shared table renderer by the caller, so spreadsheet
// semantics (header rows, per-row records) are identical to XLSX/CSV/TSV.
func extractBIFF(stream []byte) (Document, error) {
	document := Document{Kind: KindExcel}
	if len(stream) == 0 {
		return document, errors.New("workbook stream is empty")
	}

	shared := &biffStringTable{}
	sheeted := map[uint32]cellGrid{}
	var (
		records        int
		offset         uint32
		sheetPositions []uint32
		encrypted      bool
	)
	collecting := false

	for pos := 0; pos+4 <= len(stream); {
		records++
		if records > MaxBIFFRecords {
			document.Limitations = append(document.Limitations, "workbook record limit reached; extraction truncated")
			break
		}
		recordType := binary.LittleEndian.Uint16(stream[pos:])
		length := int(binary.LittleEndian.Uint16(stream[pos+2:]))
		payloadStart := pos + 4
		payloadEnd := payloadStart + length
		if payloadEnd > len(stream) {
			break
		}
		payload := stream[payloadStart:payloadEnd]
		pos = payloadEnd

		switch recordType {
		case biffRecordFilePass:
			encrypted = true
		case biffRecordBoundSheet:
			if len(payload) >= 4 {
				sheetPositions = append(sheetPositions, binary.LittleEndian.Uint32(payload))
			}
		case biffRecordSST:
			shared.append(payload, false)
		case biffRecordContinue:
			shared.append(payload, true)
		case biffRecordBOF:
			if len(payload) >= 4 && binary.LittleEndian.Uint16(payload[2:]) == 0x0010 {
				// A worksheet substream began; remember where it is.
				offset = uint32(payloadStart - 4)
				collecting = true
				if _, exists := sheeted[offset]; !exists {
					sheeted[offset] = cellGrid{}
				}
			}
		case biffRecordEOF:
			collecting = false
		}

		if !collecting {
			continue
		}
		grid := sheeted[offset]
		switch recordType {
		case biffRecordLabelSST:
			if len(payload) >= 10 {
				row := int(binary.LittleEndian.Uint16(payload))
				column := int(binary.LittleEndian.Uint16(payload[2:]))
				index := int(binary.LittleEndian.Uint32(payload[6:]))
				if text, ok := shared.at(index); ok {
					grid.set(row, column, text)
				}
			}
		case biffRecordLabel:
			if len(payload) >= 6 {
				row := int(binary.LittleEndian.Uint16(payload))
				column := int(binary.LittleEndian.Uint16(payload[2:]))
				if text, ok := decodeUnicodeString(payload[6:], 2, false); ok {
					grid.set(row, column, text)
				}
			}
		case biffRecordRK:
			if len(payload) >= 10 {
				row := int(binary.LittleEndian.Uint16(payload))
				column := int(binary.LittleEndian.Uint16(payload[2:]))
				grid.set(row, column, formatNumber(decodeRK(binary.LittleEndian.Uint32(payload[6:]))))
			}
		case biffRecordMulRK:
			if len(payload) >= 6 {
				row := int(binary.LittleEndian.Uint16(payload))
				first := int(binary.LittleEndian.Uint16(payload[2:]))
				entries := (len(payload) - 6) / 6
				for entry := 0; entry < entries; entry++ {
					value := binary.LittleEndian.Uint32(payload[4+entry*6+2:])
					grid.set(row, first+entry, formatNumber(decodeRK(value)))
				}
			}
		case biffRecordNumber:
			if len(payload) >= 14 {
				row := int(binary.LittleEndian.Uint16(payload))
				column := int(binary.LittleEndian.Uint16(payload[2:]))
				value := math.Float64frombits(binary.LittleEndian.Uint64(payload[6:]))
				grid.set(row, column, formatNumber(value))
			}
		case biffRecordBoolErr:
			if len(payload) >= 8 && payload[7] == 0 {
				row := int(binary.LittleEndian.Uint16(payload))
				column := int(binary.LittleEndian.Uint16(payload[2:]))
				if payload[6] != 0 {
					grid.set(row, column, "TRUE")
				} else {
					grid.set(row, column, "FALSE")
				}
			}
		}
		sheeted[offset] = grid
	}

	if encrypted {
		document.Encrypted = true
		document.Status = StatusEncrypted
		document.Limitations = append(document.Limitations, "workbook is encrypted; content was not inspected")
		return document, nil
	}
	if len(sheeted) == 0 {
		return document, errors.New("workbook contains no worksheet")
	}

	// Sheets are emitted in BOUNDSHEET order when available so the grid matches
	// the workbook's visible order; the remainder is appended deterministically.
	order := make([]uint32, 0, len(sheeted))
	for _, position := range sheetPositions {
		if _, ok := sheeted[position]; ok {
			order = append(order, position)
		}
	}
	remaining := make([]uint32, 0, len(sheeted))
	for position := range sheeted {
		known := false
		for _, candidate := range order {
			if candidate == position {
				known = true
				break
			}
		}
		if !known {
			remaining = append(remaining, position)
		}
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i] < remaining[j] })
	order = append(order, remaining...)
	if len(order) > MaxSheets {
		order = order[:MaxSheets]
	}

	total := 0
	for _, position := range order {
		grid := sheeted[position].rows()
		total += countCells(grid)
		if total > MaxCells {
			document.Limitations = append(document.Limitations, "cell limit reached; extraction truncated")
			break
		}
		if len(grid) > 0 {
			document.Grid = append(document.Grid, grid...)
		}
	}
	return document, nil
}

// cellGrid collects sparse cells before they are materialized as rows.
type cellGrid map[int]map[int]string

func (g cellGrid) set(row, column int, value string) {
	if row < 0 || column < 0 || len(value) > MaxCellChars {
		return
	}
	if g[row] == nil {
		g[row] = map[int]string{}
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	g[row][column] = value
}

func (g cellGrid) rows() [][]string {
	if len(g) == 0 {
		return nil
	}
	rows := make([]int, 0, len(g))
	for row := range g {
		rows = append(rows, row)
	}
	sort.Ints(rows)
	grid := make([][]string, 0, len(rows))
	for _, row := range rows {
		columns := make([]int, 0, len(g[row]))
		for column := range g[row] {
			columns = append(columns, column)
		}
		sort.Ints(columns)
		width := columns[len(columns)-1] + 1
		if width > 1024 {
			width = 1024
		}
		rowCells := make([]string, width)
		for _, column := range columns {
			if column < width {
				rowCells[column] = g[row][column]
			}
		}
		grid = append(grid, rowCells)
	}
	return grid
}

func countCells(grid [][]string) int {
	total := 0
	for _, row := range grid {
		total += len(row)
	}
	return total
}

// biffStringTable holds the SST, including strings continued across CONTINUE
// records (each continuation restarts with a fresh option byte).
type biffStringTable struct {
	segments [][]byte
	strings  []string
	parsed   bool
}

func (t *biffStringTable) append(payload []byte, continuation bool) {
	t.segments = append(t.segments, payload)
	_ = continuation
	t.parsed = false
}

func (t *biffStringTable) at(index int) (string, bool) {
	if !t.parsed {
		t.parse()
	}
	if index < 0 || index >= len(t.strings) {
		return "", false
	}
	return t.strings[index], true
}

func (t *biffStringTable) parse() {
	t.parsed = true
	if len(t.segments) == 0 {
		return
	}
	reader := &biffReader{segments: t.segments}
	total, ok := reader.u32()
	if !ok {
		return
	}
	unique, ok := reader.u32()
	if !ok {
		return
	}
	_ = total
	for index := 0; index < int(unique) && index < MaxCells; index++ {
		text, ok := reader.string(2)
		if !ok {
			return
		}
		t.strings = append(t.strings, text)
	}
}

// biffReader walks SST payload segments, following string continuations.
type biffReader struct {
	segments [][]byte
	segment  int
	offset   int
}

func (r *biffReader) byteAt() (byte, bool) {
	for r.segment < len(r.segments) {
		current := r.segments[r.segment]
		if r.offset < len(current) {
			value := current[r.offset]
			r.offset++
			return value, true
		}
		r.segment++
		r.offset = 0
	}
	return 0, false
}

func (r *biffReader) u16() (uint16, bool) {
	low, ok := r.byteAt()
	if !ok {
		return 0, false
	}
	high, ok := r.byteAt()
	if !ok {
		return 0, false
	}
	return uint16(low) | uint16(high)<<8, true
}

func (r *biffReader) u32() (uint32, bool) {
	low, ok := r.u16()
	if !ok {
		return 0, false
	}
	high, ok := r.u16()
	if !ok {
		return 0, false
	}
	return uint32(low) | uint32(high)<<16, true
}

// string reads one BIFF8 unicode string whose character count is lengthBytes
// wide (2 inside the SST, 1 for sheet names).
func (r *biffReader) string(lengthBytes int) (string, bool) {
	characters, ok := r.charCount(lengthBytes)
	if !ok {
		return "", false
	}
	options, ok := r.byteAt()
	if !ok {
		return "", false
	}
	highByte := options&0x01 != 0
	richRuns := 0
	extendedSize := 0
	if options&0x08 != 0 {
		runs, ok := r.u16()
		if !ok {
			return "", false
		}
		richRuns = int(runs)
	}
	if options&0x04 != 0 {
		size, ok := r.u32()
		if !ok {
			return "", false
		}
		extendedSize = int(size)
	}
	text, ok := r.characters(characters, highByte)
	if !ok {
		return "", false
	}
	for index := 0; index < richRuns; index++ {
		if _, ok := r.u32(); !ok {
			return "", false
		}
	}
	for index := 0; index < extendedSize; index++ {
		if _, ok := r.byteAt(); !ok {
			return "", false
		}
	}
	return text, true
}

func (r *biffReader) charCount(lengthBytes int) (int, bool) {
	if lengthBytes == 1 {
		value, ok := r.byteAt()
		return int(value), ok
	}
	value, ok := r.u16()
	return int(value), ok
}

// characters decodes a character run, switching segments when a string is
// continued. A continuation restarts with a fresh option byte that governs the
// remainder of that string.
func (r *biffReader) characters(count int, highByte bool) (string, bool) {
	var (
		units []uint16
		bytes []byte
	)
	for index := 0; index < count; index++ {
		if highByte {
			unit, ok := r.u16()
			if !ok {
				break
			}
			units = append(units, unit)
		} else {
			b, ok := r.byteAt()
			if !ok {
				break
			}
			bytes = append(bytes, b)
		}
		// A string that runs past the current segment continues in the next one,
		// which repeats the option byte for the remainder.
		if r.offset >= len(r.segments[r.segment]) && index+1 < count {
			r.segment++
			r.offset = 0
			options, ok := r.byteAt()
			if !ok {
				break
			}
			highByte = options&0x01 != 0
		}
	}
	var builder strings.Builder
	if len(units) > 0 {
		builder.WriteString(string(utf16.Decode(units)))
	}
	if len(bytes) > 0 {
		decoded, err := charmap.Windows1252.NewDecoder().Bytes(bytes)
		if err == nil {
			builder.WriteString(string(decoded))
		}
	}
	if builder.Len() > MaxCellChars {
		return builder.String()[:MaxCellChars], true
	}
	return builder.String(), true
}

// decodeUnicodeString decodes a BIFF8 unicode string at the start of payload.
func decodeUnicodeString(payload []byte, lengthBytes int, highDefault bool) (string, bool) {
	reader := &biffReader{segments: [][]byte{payload}}
	text, ok := reader.string(lengthBytes)
	if !ok {
		return "", false
	}
	_ = highDefault
	return text, true
}

// decodeRK expands the BIFF RK packed number format.
func decodeRK(value uint32) float64 {
	multiplier := 1.0
	if value&0x01 != 0 {
		multiplier = 0.01
	}
	if value&0x02 != 0 {
		// 30-bit signed integer in the high bits.
		integer := int32(value) >> 2
		return float64(integer) * multiplier
	}
	// 30-bit IEEE float in the high bits.
	bits := uint64(value&0xFFFFFFFC) << 32
	return math.Float64frombits(bits) * multiplier
}

func formatNumber(value float64) string {
	if value == math.Trunc(value) && math.Abs(value) < 1e15 {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}

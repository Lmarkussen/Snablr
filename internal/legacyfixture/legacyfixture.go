// Package legacyfixture builds real OLE/CFB legacy Office documents (Word
// 97-2003, Excel 97-2003) for regression fixtures. Files are assembled from the
// documented on-disk structures so the parser under test reads genuine
// containers rather than hand-waved byte blobs.
package legacyfixture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	sectorSize = 512
	miniCutoff = 4096
	freeSector = 0xFFFFFFFF
	endOfChain = 0xFFFFFFFE
	noStream   = 0xFFFFFFFF
)

// CFB assembles a compound file with the given streams. Streams are padded to
// the mini-stream cutoff so they are stored in the regular FAT, which keeps the
// writer small while producing a valid container.
func CFB(streams map[string][]byte) []byte {
	names := make([]string, 0, len(streams))
	for name := range streams {
		names = append(names, name)
	}
	sort.Strings(names)

	// Layout: header (1 sector) | directory sectors | stream sectors.
	directorySectors := (len(names) + 1) * 128 / sectorSize
	if (len(names)+1)*128%sectorSize != 0 {
		directorySectors++
	}
	firstDirSector := uint32(1)
	nextSector := firstDirSector + uint32(directorySectors)

	type placement struct {
		name        string
		startSector uint32
		size        uint64
		data        []byte
	}
	placements := make([]placement, 0, len(names))
	for _, name := range names {
		data := streams[name]
		padded := data
		for len(padded) < miniCutoff {
			padded = append(padded, 0)
		}
		if rem := len(padded) % sectorSize; rem != 0 {
			padded = append(padded, make([]byte, sectorSize-rem)...)
		}
		// The padded length is recorded so the stream is read through the regular
		// FAT: the CFB mini-stream is not modelled by this fixture writer.
		placements = append(placements, placement{name: name, startSector: nextSector, size: uint64(len(padded)), data: padded})
		nextSector += uint32(len(padded) / sectorSize)
	}
	totalSectors := nextSector + 1 // + FAT sector
	fatSector := nextSector

	// Layout: 512-byte header, then the sectors themselves.
	file := make([]byte, (int(totalSectors)+1)*sectorSize)

	// --- header ---
	header := file[:sectorSize]
	copy(header[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(header[0x18:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(header[0x1A:], 0x0003) // major version (512-byte sectors)
	binary.LittleEndian.PutUint16(header[0x1C:], 0xFFFE) // little endian
	binary.LittleEndian.PutUint16(header[0x1E:], 9)      // sector shift
	binary.LittleEndian.PutUint16(header[0x20:], 6)      // mini sector shift
	binary.LittleEndian.PutUint32(header[0x2C:], 1)      // number of FAT sectors
	binary.LittleEndian.PutUint32(header[0x30:], firstDirSector)
	binary.LittleEndian.PutUint32(header[0x38:], miniCutoff)
	binary.LittleEndian.PutUint32(header[0x3C:], endOfChain) // first mini FAT sector
	binary.LittleEndian.PutUint32(header[0x40:], 0)          // mini FAT count
	binary.LittleEndian.PutUint32(header[0x44:], endOfChain) // first DIFAT sector
	binary.LittleEndian.PutUint32(header[0x48:], 0)          // DIFAT count
	for index := 0; index < 109; index++ {
		offset := 0x4C + index*4
		binary.LittleEndian.PutUint32(header[offset:], freeSector)
	}
	binary.LittleEndian.PutUint32(header[0x4C:], fatSector)

	// --- directory ---
	directory := file[(int(firstDirSector)+1)*sectorSize:]
	writeDirEntry := func(index int, name string, objectType byte, startSector uint32, size uint64, child, right uint32) {
		entry := directory[index*128 : (index+1)*128]
		encoded := utf16.Encode([]rune(name))
		for i, unit := range encoded {
			if i*2+2 > 64 {
				break
			}
			binary.LittleEndian.PutUint16(entry[i*2:], unit)
		}
		binary.LittleEndian.PutUint16(entry[64:], uint16((len(encoded)+1)*2))
		entry[66] = objectType
		entry[67] = 1 // black
		binary.LittleEndian.PutUint32(entry[68:], noStream)
		binary.LittleEndian.PutUint32(entry[72:], right)
		binary.LittleEndian.PutUint32(entry[76:], child)
		binary.LittleEndian.PutUint32(entry[116:], startSector)
		binary.LittleEndian.PutUint64(entry[120:], size)
	}
	// Root entry: child points at the first stream; streams are a right-linked
	// list, which the CFB reader traverses without requiring ordering.
	writeDirEntry(0, "Root Entry", 5, endOfChain, 0, 1, noStream)
	for index, placement := range placements {
		right := uint32(noStream)
		if index+1 < len(placements) {
			right = uint32(index + 2)
		}
		writeDirEntry(index+1, placement.name, 2, placement.startSector, placement.size, noStream, right)
	}

	// --- stream sectors ---
	for _, placement := range placements {
		offset := (int(placement.startSector) + 1) * sectorSize
		copy(file[offset:], placement.data)
	}

	// --- FAT ---
	fat := file[(int(fatSector)+1)*sectorSize:]
	for index := 0; index < sectorSize/4; index++ {
		binary.LittleEndian.PutUint32(fat[index*4:], freeSector)
	}
	// Directory chain.
	binary.LittleEndian.PutUint32(fat[int(firstDirSector)*4:], endOfChain)
	if directorySectors > 1 {
		binary.LittleEndian.PutUint32(fat[int(firstDirSector)*4:], firstDirSector+1)
		for sector := 1; sector < directorySectors; sector++ {
			value := uint32(endOfChain)
			if sector+1 < directorySectors {
				value = firstDirSector + uint32(sector) + 1
			}
			binary.LittleEndian.PutUint32(fat[int(firstDirSector+uint32(sector))*4:], value)
		}
	}
	for _, placement := range placements {
		count := len(placement.data) / sectorSize
		for index := 0; index < count; index++ {
			value := uint32(endOfChain)
			if index+1 < count {
				value = placement.startSector + uint32(index) + 1
			}
			binary.LittleEndian.PutUint32(fat[int(placement.startSector+uint32(index))*4:], value)
		}
	}
	binary.LittleEndian.PutUint32(fat[int(fatSector)*4:], 0xFFFFFFFD) // FATSECT
	return file
}

// Word builds a Word 97-2003 document whose text is stored as one UTF-16LE
// piece. Paragraphs are separated by \r; table rows should use \x07 cell and
// row marks.
func Word(text string) []byte {
	return wordDocument([]piece{{text: text, compressed: false}}, false)
}

// WordCP1252 builds a Word 97-2003 document whose text is stored as a
// compressed (single-byte CP1252) piece, exercising the ANSI path.
func WordCP1252(text string) []byte {
	return wordDocument([]piece{{text: text, compressed: true}}, false)
}

// WordMixed builds a document with one CP1252 piece followed by one UTF-16LE
// piece, which is how Word stores text after mixed edits.
func WordMixed(compressedText, unicodeText string) []byte {
	return wordDocument([]piece{
		{text: compressedText, compressed: true},
		{text: unicodeText, compressed: false},
	}, false)
}

// WordEncrypted builds an encrypted (password-protected) Word document shell.
func WordEncrypted() []byte {
	return wordDocument([]piece{{text: "Brukernavn: hidden\rPassord: hidden\r", compressed: false}}, true)
}

// WordTable renders a table as Word table text: each cell ends with \x07 and the
// row ends with the row mark (\x07\x07).
func WordTable(rows ...[]string) []byte {
	var builder strings.Builder
	for _, row := range rows {
		for _, cell := range row {
			builder.WriteString(cell)
			builder.WriteString("\x07")
		}
		builder.WriteString("\x07\r")
	}
	return Word(builder.String())
}

type piece struct {
	text       string
	compressed bool
}

func wordDocument(pieces []piece, encrypted bool) []byte {
	// WordDocument stream: FIB then the text pieces.
	const textStart = 0x0400
	doc := make([]byte, textStart)
	binary.LittleEndian.PutUint16(doc[0x00:], 0xA5EC) // wIdent
	binary.LittleEndian.PutUint16(doc[0x02:], 0x00C1) // nFib (Word 97)
	binary.LittleEndian.PutUint16(doc[0x06:], 0x0414) // lid: Norwegian Bokmål
	flags := uint16(0x0200)                           // fWhichTblStm: use 1Table
	if encrypted {
		flags |= 0x0100
	}
	binary.LittleEndian.PutUint16(doc[0x0A:], flags)
	binary.LittleEndian.PutUint16(doc[0x20:], 14)     // csw
	binary.LittleEndian.PutUint16(doc[0x3E:], 22)     // cslw
	binary.LittleEndian.PutUint16(doc[0x98:], 0x005D) // cbRgFcLcb

	var (
		text      []byte
		cps       []uint32
		pcds      [][]byte
		charCount uint32
	)
	for _, current := range pieces {
		raw := []byte(current.text)
		offset := len(doc) + len(text)
		if current.compressed {
			encoded := encodeCP1252(current.text)
			cps = append(cps, charCount)
			charCount += uint32(len(encoded))
			pcd := make([]byte, 8)
			fc := uint32(offset*2) | 0x40000000
			binary.LittleEndian.PutUint32(pcd[2:], fc)
			pcds = append(pcds, pcd)
			text = append(text, encoded...)
			continue
		}
		units := utf16.Encode([]rune(string(raw)))
		encoded := make([]byte, 0, len(units)*2)
		for _, unit := range units {
			var buffer [2]byte
			binary.LittleEndian.PutUint16(buffer[:], unit)
			encoded = append(encoded, buffer[:]...)
		}
		cps = append(cps, charCount)
		charCount += uint32(len(units))
		pcd := make([]byte, 8)
		binary.LittleEndian.PutUint32(pcd[2:], uint32(offset))
		pcds = append(pcds, pcd)
		text = append(text, encoded...)
	}
	cps = append(cps, charCount)
	doc = append(doc, text...)
	binary.LittleEndian.PutUint32(doc[0x4C:], charCount) // ccpText

	// Table stream: CLX with a single Pcdt.
	plc := make([]byte, 0, len(cps)*4+len(pcds)*8)
	for _, cp := range cps {
		var buffer [4]byte
		binary.LittleEndian.PutUint32(buffer[:], cp)
		plc = append(plc, buffer[:]...)
	}
	for _, pcd := range pcds {
		plc = append(plc, pcd...)
	}
	table := make([]byte, 0, len(plc)+5)
	table = append(table, 0x02)
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(plc)))
	table = append(table, length[:]...)
	table = append(table, plc...)
	binary.LittleEndian.PutUint32(doc[0x01A2:], 0)                  // fcClx
	binary.LittleEndian.PutUint32(doc[0x01A6:], uint32(len(table))) // lcbClx

	return CFB(map[string][]byte{"WordDocument": doc, "1Table": table})
}

func encodeCP1252(text string) []byte {
	var buffer bytes.Buffer
	for _, r := range text {
		switch {
		case r < 0x100:
			buffer.WriteByte(byte(r))
		case r == 'æ':
			buffer.WriteByte(0xE6)
		case r == 'ø':
			buffer.WriteByte(0xF8)
		case r == 'å':
			buffer.WriteByte(0xE5)
		case r == 'Æ':
			buffer.WriteByte(0xC6)
		case r == 'Ø':
			buffer.WriteByte(0xD8)
		case r == 'Å':
			buffer.WriteByte(0xC5)
		case r == '–':
			buffer.WriteByte(0x96)
		default:
			buffer.WriteByte('?')
		}
	}
	return buffer.Bytes()
}

// Workbook builds a BIFF8 workbook with one sheet holding the given rows.
// Text cells use the shared string table, numbers use NUMBER records.
func Workbook(rows [][]string) []byte {
	var shared []string
	index := map[string]int{}
	type cell struct {
		row, column int
		text        string
		number      *float64
	}
	var cells []cell
	for rowIndex, row := range rows {
		for columnIndex, value := range row {
			if value == "" {
				continue
			}
			if number, ok := parseNumber(value); ok {
				cells = append(cells, cell{row: rowIndex, column: columnIndex, number: &number})
				continue
			}
			if _, ok := index[value]; !ok {
				index[value] = len(shared)
				shared = append(shared, value)
			}
			cells = append(cells, cell{row: rowIndex, column: columnIndex, text: value})
		}
	}

	var globals bytes.Buffer
	writeRecord(&globals, 0x0809, bofPayload(0x0005))
	// BOUNDSHEET is patched once the sheet offset is known.
	sheetOffsetPlaceholder := globals.Len()
	sheetName := "Ark1"
	writeRecord(&globals, 0x0085, append([]byte{0, 0, 0, 0, 0, 0}, biffShortString(sheetName)...))
	sst := biffSST(shared)
	writeRecord(&globals, 0x00FC, sst)
	writeRecord(&globals, 0x000A, nil) // EOF

	var sheet bytes.Buffer
	sheetOffset := uint32(globals.Len())
	writeRecord(&sheet, 0x0809, bofPayload(0x0010))
	for _, item := range cells {
		payload := make([]byte, 6)
		binary.LittleEndian.PutUint16(payload[0:], uint16(item.row))
		binary.LittleEndian.PutUint16(payload[2:], uint16(item.column))
		if item.number != nil {
			payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0)
			binary.LittleEndian.PutUint64(payload[6:], math.Float64bits(*item.number))
			writeRecord(&sheet, 0x0203, payload)
			continue
		}
		payload = append(payload, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(payload[6:], uint32(index[item.text]))
		writeRecord(&sheet, 0x00FD, payload)
	}
	writeRecord(&sheet, 0x000A, nil)

	workbook := append(globals.Bytes(), sheet.Bytes()...)
	binary.LittleEndian.PutUint32(workbook[sheetOffsetPlaceholder+4:], sheetOffset)

	// The workbook stream must be at least the mini-stream cutoff so it is
	// stored through the regular FAT; CFB pads it.
	return CFB(map[string][]byte{"Workbook": workbook})
}

// WorkbookEncrypted builds a workbook with a FILEPASS record.
func WorkbookEncrypted() []byte {
	var stream bytes.Buffer
	writeRecord(&stream, 0x0809, bofPayload(0x0005))
	writeRecord(&stream, 0x002F, make([]byte, 6))
	writeRecord(&stream, 0x000A, nil)
	return CFB(map[string][]byte{"Workbook": stream.Bytes()})
}

func bofPayload(documentType uint16) []byte {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint16(payload[0:], 0x0600) // BIFF8
	binary.LittleEndian.PutUint16(payload[2:], documentType)
	binary.LittleEndian.PutUint16(payload[4:], 0x0DBB) // build
	binary.LittleEndian.PutUint16(payload[6:], 0x07CC) // year 1996
	return payload
}

func biffSST(stringsIn []string) []byte {
	var payload bytes.Buffer
	count := make([]byte, 8)
	binary.LittleEndian.PutUint32(count[0:], uint32(len(stringsIn)))
	binary.LittleEndian.PutUint32(count[4:], uint32(len(stringsIn)))
	payload.Write(count)
	for _, value := range stringsIn {
		payload.Write(biffUnicodeString(value))
	}
	return payload.Bytes()
}

func biffUnicodeString(value string) []byte {
	units := utf16.Encode([]rune(value))
	payload := make([]byte, 3)
	binary.LittleEndian.PutUint16(payload[0:], uint16(len(units)))
	payload[2] = 0x01 // fHighByte: UTF-16LE
	for _, unit := range units {
		var buffer [2]byte
		binary.LittleEndian.PutUint16(buffer[:], unit)
		payload = append(payload, buffer[:]...)
	}
	return payload
}

func biffShortString(value string) []byte {
	encoded := []byte(value)
	payload := append([]byte{byte(len(encoded)), 0x00}, encoded...)
	return payload
}

func writeRecord(buffer *bytes.Buffer, recordType uint16, payload []byte) {
	var header [4]byte
	binary.LittleEndian.PutUint16(header[0:], recordType)
	binary.LittleEndian.PutUint16(header[2:], uint16(len(payload)))
	buffer.Write(header[:])
	buffer.Write(payload)
}

func parseNumber(value string) (float64, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.ContainsAny(trimmed, "abcdefghijklmnopqrstuvwxyzæøåABCDEFGHIJKLMNOPQRSTUVWXYZÆØÅ!@#:;") {
		return 0, false
	}
	var number float64
	if _, err := fmt.Sscan(trimmed, &number); err != nil {
		return 0, false
	}
	return number, true
}

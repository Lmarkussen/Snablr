package legacyoffice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/encoding/charmap"
)

// Word Binary File Format (MS-DOC) constants used for read-only text recovery.
const (
	wordFibMagic          = 0xA5EC
	wordFibFlagsOffset    = 0x000A
	wordFibEncrypted      = 0x0100
	wordFibWhichTableStm  = 0x0200
	wordFibFcClxOffset    = 0x01A2
	wordFibMinSize        = 0x0200
	wordCompressedFcFlag  = 0x40000000
	wordPieceFcMask       = 0x3FFFFFFF
	wordClxPrcStart       = 0x01
	wordClxPcdtStart      = 0x02
	wordPlcPcdHeaderBytes = 4
	wordPcdSize           = 8
)

// extractWord reconstructs visible document text from the WordDocument stream
// and its piece table. Only text recovery is implemented: no layout, no
// editing, no rendering.
func extractWord(streams map[string][]byte) (Document, error) {
	document := Document{Kind: KindWord}
	doc := streams["worddocument"]
	if len(doc) < wordFibMinSize {
		return document, errors.New("WordDocument stream is truncated")
	}
	if binary.LittleEndian.Uint16(doc[0:2]) != wordFibMagic {
		return document, errors.New("invalid Word FIB signature")
	}
	flags := binary.LittleEndian.Uint16(doc[wordFibFlagsOffset:])
	if flags&wordFibEncrypted != 0 {
		document.Encrypted = true
		document.Status = StatusEncrypted
		document.Limitations = append(document.Limitations, "document is encrypted; content was not inspected")
		return document, nil
	}

	tableName := "0table"
	if flags&wordFibWhichTableStm != 0 {
		tableName = "1table"
	}
	table := streams[tableName]
	if len(table) == 0 {
		// Some writers only populate one table stream; fall back to the other so
		// a valid piece table is not missed.
		if tableName == "0table" {
			table = streams["1table"]
		} else {
			table = streams["0table"]
		}
	}
	if len(table) == 0 {
		return document, errors.New("word table stream is missing")
	}

	fcClx := binary.LittleEndian.Uint32(doc[wordFibFcClxOffset : wordFibFcClxOffset+4])
	lcbClx := binary.LittleEndian.Uint32(doc[wordFibFcClxOffset+4 : wordFibFcClxOffset+8])
	if lcbClx == 0 {
		return document, errors.New("word piece table is empty")
	}
	if int64(fcClx)+int64(lcbClx) > int64(len(table)) {
		return document, errors.New("word piece table is outside the table stream")
	}
	clx := table[fcClx : fcClx+lcbClx]

	plc, err := pieceTable(clx)
	if err != nil {
		return document, err
	}
	text, err := pieceText(doc, plc)
	if err != nil {
		return document, err
	}
	document.Text = normalizeText(text)
	return document, nil
}

// pieceTable returns the PlcPcd payload from a CLX, skipping any property
// modifiers (Prc) that precede it.
func pieceTable(clx []byte) ([]byte, error) {
	for index := 0; index < len(clx); {
		switch clx[index] {
		case wordClxPrcStart:
			if index+3 > len(clx) {
				return nil, errors.New("truncated CLX property modifier")
			}
			size := int(binary.LittleEndian.Uint16(clx[index+1:]))
			index += 3 + size
		case wordClxPcdtStart:
			if index+5 > len(clx) {
				return nil, errors.New("truncated CLX piece table")
			}
			size := int(binary.LittleEndian.Uint32(clx[index+1:]))
			start := index + 5
			if size <= 0 || start+size > len(clx) {
				return nil, errors.New("CLX piece table is outside the stream")
			}
			return clx[start : start+size], nil
		default:
			return nil, fmt.Errorf("unexpected CLX entry 0x%02x", clx[index])
		}
	}
	return nil, errors.New("CLX contains no piece table")
}

// pieceText decodes every text piece described by the piece table.
func pieceText(doc []byte, plc []byte) (string, error) {
	if len(plc) < wordPlcPcdHeaderBytes+wordPcdSize {
		return "", errors.New("piece table is too small")
	}
	count := (len(plc) - wordPlcPcdHeaderBytes) / (4 + wordPcdSize)
	if count <= 0 {
		return "", errors.New("piece table contains no pieces")
	}
	if count > MaxPieces {
		count = MaxPieces
	}
	cpOffset := 0
	pcdOffset := 4 * (count + 1)

	var builder strings.Builder
	for piece := 0; piece < count; piece++ {
		cpStart := binary.LittleEndian.Uint32(plc[cpOffset+piece*4:])
		cpEnd := binary.LittleEndian.Uint32(plc[cpOffset+(piece+1)*4:])
		if cpEnd < cpStart {
			return "", errors.New("piece table character positions are not ordered")
		}
		characters := int(cpEnd - cpStart)
		if characters <= 0 {
			continue
		}
		entry := plc[pcdOffset+piece*wordPcdSize:]
		fc := binary.LittleEndian.Uint32(entry[2:6])
		compressed := fc&wordCompressedFcFlag != 0
		offset := int(fc & wordPieceFcMask)
		if compressed {
			offset /= 2
		}
		text, err := decodePiece(doc, offset, characters, compressed)
		if err != nil {
			return "", err
		}
		builder.WriteString(text)
		if builder.Len() >= MaxTextBytes {
			break
		}
	}
	return builder.String(), nil
}

// decodePiece reads one text piece. Compressed pieces are single-byte CP1252;
// uncompressed pieces are UTF-16LE.
func decodePiece(doc []byte, offset, characters int, compressed bool) (string, error) {
	byteCount := characters
	if !compressed {
		if characters > (1<<31-1)/2 {
			return "", errors.New("piece length is not representable")
		}
		byteCount = characters * 2
	}
	if offset < 0 || offset > len(doc) || byteCount > len(doc)-offset {
		return "", errors.New("text piece is outside the WordDocument stream")
	}
	raw := doc[offset : offset+byteCount]
	if compressed {
		decoded, err := charmap.Windows1252.NewDecoder().Bytes(raw)
		if err != nil {
			return "", fmt.Errorf("decode CP1252 text piece: %w", err)
		}
		return string(decoded), nil
	}
	units := make([]uint16, 0, characters)
	for index := 0; index+1 < len(raw); index += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[index:]))
	}
	return string(utf16.Decode(units)), nil
}

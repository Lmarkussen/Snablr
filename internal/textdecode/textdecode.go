package textdecode

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

const sampleLimit = 4096

func Normalize(content []byte) string {
	text, ok := Decode(content)
	if !ok {
		return ""
	}
	return text
}

func Decode(content []byte) (string, bool) {
	if len(content) == 0 {
		return "", false
	}

	s := sample(content)
	if utf8.Valid(content) {
		if !looksUTF8Text(s) {
			return "", false
		}
		return normalizeString(string(content)), true
	}

	if text, ok := decodeUTF16(content); ok {
		return normalizeString(text), true
	}

	if bytes.IndexByte(s, 0x00) >= 0 {
		return "", false
	}

	if !looksLikeSingleByteText(s) {
		return "", false
	}

	if text, ok := decodeSingleByte(content); ok {
		return normalizeString(text), true
	}

	return "", false
}

func LooksLikeText(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	s := sample(content)
	if utf8.Valid(s) {
		return looksUTF8Text(s)
	}
	if _, ok := decodeUTF16(s); ok {
		return true
	}
	if bytes.IndexByte(s, 0x00) >= 0 {
		return false
	}
	if !looksLikeSingleByteText(s) {
		return false
	}
	return looksLikeDecodedSingleByteSample(s)
}

func decodeUTF16(content []byte) (string, bool) {
	switch {
	case len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE:
		return decodeUTF16WithOrder(content[2:], binary.LittleEndian)
	case len(content) >= 2 && content[0] == 0xFE && content[1] == 0xFF:
		return decodeUTF16WithOrder(content[2:], binary.BigEndian)
	}

	order, ok := detectUTF16Heuristic(sample(content))
	if !ok {
		return "", false
	}
	return decodeUTF16WithOrder(content, order)
}

func decodeUTF16WithOrder(content []byte, order binary.ByteOrder) (string, bool) {
	if len(content) < 2 {
		return "", false
	}
	if len(content)%2 != 0 {
		content = content[:len(content)-1]
	}
	u16 := make([]uint16, 0, len(content)/2)
	for i := 0; i+1 < len(content); i += 2 {
		u16 = append(u16, order.Uint16(content[i:]))
	}
	text := string(utf16.Decode(u16))
	if !looksDecodedText(text) {
		return "", false
	}
	return text, true
}

func detectUTF16Heuristic(content []byte) (binary.ByteOrder, bool) {
	if len(content) < 4 {
		return nil, false
	}
	if len(content)%2 != 0 {
		content = content[:len(content)-1]
	}
	pairs := len(content) / 2
	if pairs == 0 {
		return nil, false
	}

	var evenZero, oddZero int
	for i := 0; i+1 < len(content); i += 2 {
		if content[i] == 0x00 {
			evenZero++
		}
		if content[i+1] == 0x00 {
			oddZero++
		}
	}

	evenRatio := float64(evenZero) / float64(pairs)
	oddRatio := float64(oddZero) / float64(pairs)
	switch {
	case oddRatio >= 0.30 && evenRatio <= 0.05:
		return binary.LittleEndian, true
	case evenRatio >= 0.30 && oddRatio <= 0.05:
		return binary.BigEndian, true
	default:
		return nil, false
	}
}

func decodeSingleByte(content []byte) (string, bool) {
	if !looksLikeSingleByteText(sample(content)) {
		return "", false
	}

	bestText, bestScore := bestDecodedSingleByte(content)
	if bestScore < 0.90 || !looksDecodedText(bestText) {
		return "", false
	}
	return bestText, true
}

func looksLikeSingleByteText(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	var printable, control int
	for _, b := range content {
		switch {
		case b == '\n' || b == '\r' || b == '\t' || b == ' ':
			printable++
		case b >= 32 && b <= 126:
			printable++
		case b >= 0x80:
			printable++
		default:
			control++
		}
	}
	if float64(printable)/float64(len(content)) < 0.85 {
		return false
	}
	if float64(control)/float64(len(content)) > 0.05 {
		return false
	}
	return bytes.IndexAny(content, " \n\r\t=;:,[]{}<>/\\") >= 0
}

func looksDecodedText(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	return decodedTextScore(text) >= 0.90 && hasTextStructure(text)
}

func looksUTF8Text(content []byte) bool {
	if bytes.IndexByte(content, 0x00) >= 0 {
		return false
	}
	return looksDecodedText(string(content))
}

func decodedTextScore(text string) float64 {
	total := 0
	good := 0
	bad := 0
	for _, r := range text {
		total++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			good++
		case r == utf8.RuneError:
			bad += 2
		case r < 32 || (r >= 0x7F && r <= 0x9F):
			bad++
		case unicode.IsPrint(r):
			good++
		default:
			bad++
		}
	}
	if total == 0 {
		return 0
	}
	score := float64(good-bad) / float64(total)
	if score < 0 {
		return 0
	}
	return score
}

func normalizeString(text string) string {
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return text
}

func hasTextStructure(text string) bool {
	if strings.ContainsAny(text, " \n\r\t=;:,[]{}<>/\\") {
		return true
	}
	alnum := 0
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			alnum++
		}
	}
	return alnum >= 12
}

func looksLikeDecodedSingleByteSample(content []byte) bool {
	bestText, bestScore := bestDecodedSingleByte(content)
	return bestScore >= 0.90 && looksDecodedText(bestText)
}

func bestDecodedSingleByte(content []byte) (string, float64) {
	candidates := []*charmap.Charmap{charmap.Windows1252, charmap.ISO8859_1}
	bestText := ""
	bestScore := -1.0
	for _, candidate := range candidates {
		decoded, _, err := transform.Bytes(candidate.NewDecoder(), content)
		if err != nil {
			continue
		}
		text := string(decoded)
		score := decodedTextScore(text)
		if score > bestScore {
			bestScore = score
			bestText = text
		}
	}
	return bestText, bestScore
}

func sample(content []byte) []byte {
	if len(content) <= sampleLimit {
		return content
	}
	return content[:sampleLimit]
}

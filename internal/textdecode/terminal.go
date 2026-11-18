package textdecode

import (
	"strings"
	"unicode/utf8"
)

// StripTerminalSequences removes terminal control sequences from text so that
// content matching sees what a person reading the file would see. Coloured
// console logs, PowerShell transcripts and ANSI art embed sequences such as
// "\x1b[31m" inside otherwise plain assignments ("password=\x1b[1mSecret"),
// which hid them from content rules and the credential harvester.
//
// It removes ESC-introduced sequences (CSI, OSC, DCS/SOS/PM/APC strings,
// character-set designations and two-character escapes), their single-rune C1
// forms, other C1 controls and BEL. Text without such characters is returned
// unchanged. It is for matching only; stored evidence keeps the original bytes.
func StripTerminalSequences(text string) string {
	if !containsTerminalControl(text) {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for index := 0; index < len(text); {
		r, size := utf8.DecodeRuneInString(text[index:])
		switch {
		case r == 0x1b:
			index = skipEscape(text, index+size)
		case r == 0x9b:
			index = skipCSI(text, index+size)
		case r == 0x9d, r == 0x90, r == 0x98, r == 0x9e, r == 0x9f:
			index = skipString(text, index+size)
		case r == 0x07 || (r >= 0x80 && r <= 0x9f):
			index += size
		default:
			b.WriteString(text[index : index+size])
			index += size
		}
	}
	return b.String()
}

func containsTerminalControl(text string) bool {
	for _, r := range text {
		if r == 0x1b || r == 0x07 || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// skipEscape returns the index after the escape sequence whose ESC ended just
// before index.
func skipEscape(text string, index int) int {
	if index >= len(text) {
		return index
	}
	switch c := text[index]; {
	case c == '[':
		return skipCSI(text, index+1)
	case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
		return skipString(text, index+1)
	case c == '(' || c == ')' || c == '*' || c == '+' || c == '-' || c == '.' || c == '/' || c == '#' || c == '%':
		// Character-set designation or similar: ESC, intermediate, final.
		if index+2 <= len(text) {
			return index + 2
		}
		return len(text)
	default:
		_, size := utf8.DecodeRuneInString(text[index:])
		return index + size
	}
}

// skipCSI skips parameter and intermediate bytes up to and including the
// final byte of a control sequence.
func skipCSI(text string, index int) int {
	for index < len(text) {
		c := text[index]
		switch {
		case c >= 0x40 && c <= 0x7e:
			return index + 1
		case c >= 0x20 && c <= 0x3f:
			index++
		default:
			// Malformed sequence: stop without consuming the unexpected byte.
			return index
		}
	}
	return index
}

// skipString skips an OSC/DCS-style string up to BEL or the string
// terminator (ESC \ or U+009C).
func skipString(text string, index int) int {
	for index < len(text) {
		r, size := utf8.DecodeRuneInString(text[index:])
		switch {
		case r == 0x07 || r == 0x9c:
			return index + size
		case r == 0x1b && index+size < len(text) && text[index+size] == '\\':
			return index + size + 1
		case r == '\n':
			// An unterminated string never swallows the following lines.
			return index
		}
		index += size
	}
	return index
}

package credentialanalysis

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Python modules document their usage in docstrings, and Ansible modules
// in the EXAMPLES, DOCUMENTATION and RETURN strings. Those examples are full
// of sample logins ("username: admin" / "password: SomeSecretPassword").
// Only documentation strings are recognised: a string literal that is a
// whole statement (module, class and function docstrings) or the value of
// one of the documentation variables. Strings used as values in code are
// ordinary code.

// IsPythonSource reports whether a path is a Python source file.
func IsPythonSource(path string) bool {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".py", ".pyw":
		return true
	default:
		return false
	}
}

var pythonDocumentationAssignment = regexp.MustCompile(`^[ \t]*(?:EXAMPLES|DOCUMENTATION|RETURN|__doc__)[ \t]*=[ \t]*$`)

// MaskPythonDocumentation returns the source with every documentation
// string replaced by spaces (newlines kept, so line numbers do not move)
// and the documentation text itself, one string per entry.
func MaskPythonDocumentation(source string) (string, []string) {
	spans := pythonDocumentationSpans(source)
	if len(spans) == 0 {
		return source, nil
	}
	masked := []byte(source)
	docs := make([]string, 0, len(spans))
	for _, span := range spans {
		docs = append(docs, source[span[0]:span[1]])
		for i := span[0]; i < span[1]; i++ {
			if masked[i] != '\n' && masked[i] != '\r' {
				masked[i] = ' '
			}
		}
	}
	return string(masked), docs
}

// pythonDocumentationSpans lexes Python source just enough to find string
// literals, comments, brackets and logical lines, and returns the byte
// spans of documentation strings.
func pythonDocumentationSpans(src string) [][2]int {
	var spans [][2]int
	depth := 0
	statementStart := true // at the start of a logical line (after indentation)
	lineStart := 0         // byte offset where the current logical line starts
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '\\' && i+1 < len(src) && src[i+1] == '\n':
			i += 2 // explicit line continuation
			continue
		case c == '\n':
			i++
			if depth == 0 {
				statementStart, lineStart = true, i
			}
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			i++
			continue
		case c == ';' && depth == 0:
			i++
			statementStart, lineStart = true, i
			continue
		}
		if start, end, ok := pythonStringAt(src, i); ok {
			doc := false
			if depth == 0 && restOfLogicalLineEmpty(src, end) {
				doc = statementStart || pythonDocumentationAssignment.MatchString(src[lineStart:start])
			}
			if doc {
				spans = append(spans, [2]int{start, end})
			}
			statementStart = false
			i = end
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
		statementStart = false
		// Skip a whole identifier or number so its letters are never read
		// as a string prefix.
		if isPythonNameByte(c) {
			for i < len(src) && isPythonNameByte(src[i]) {
				i++
			}
			continue
		}
		i++
	}
	return spans
}

func isPythonNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// pythonStringAt reports a string literal (with an optional r/b/u/f
// prefix) starting at i, returning its span including the quotes.
func pythonStringAt(src string, i int) (int, int, bool) {
	j := i
	for j < len(src) && j-i < 2 && strings.IndexByte("rRbBuUfF", src[j]) >= 0 {
		j++
	}
	if j >= len(src) || (src[j] != '\'' && src[j] != '"') {
		return 0, 0, false
	}
	quote := src[j]
	triple := j+2 < len(src) && src[j+1] == quote && src[j+2] == quote
	k := j + 1
	if triple {
		k = j + 3
	}
	for k < len(src) {
		switch {
		case src[k] == '\\':
			k += 2
			continue
		case triple && k+2 < len(src) && src[k] == quote && src[k+1] == quote && src[k+2] == quote:
			return i, k + 3, true
		case !triple && src[k] == quote:
			return i, k + 1, true
		case !triple && src[k] == '\n':
			return 0, 0, false // unterminated single-line string: not a literal
		}
		k++
	}
	return 0, 0, false
}

// restOfLogicalLineEmpty reports whether only whitespace, a comment or a
// statement separator follows position i on its line.
func restOfLogicalLineEmpty(src string, i int) bool {
	for ; i < len(src); i++ {
		switch src[i] {
		case ' ', '\t', '\r', '\f':
			continue
		case '\n', '#', ';':
			return true
		default:
			return false
		}
	}
	return true
}

// harvestPythonDocumentation harvests the documentation strings of a
// Python file as plain text and keeps everything found there as review
// material: examples are kept, never confirmed and never dropped.
func harvestPythonDocumentation(input HarvestInput, docs []string, report *harvestReport, add func(Candidate)) {
	inner := input
	inner.Content = []byte(strings.Join(docs, "\n\n"))
	inner.Path = input.Path + ".documentation.txt"
	for _, candidate := range harvest(inner, report) {
		candidate.Verification = Review
		candidate.ValidationBasis = ""
		candidate.ReviewReasons = []string{"found in Python documentation (docstring or module examples)"}
		candidate.Evidence = nil
		add(candidate)
	}
}

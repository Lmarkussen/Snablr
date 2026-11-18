// Package termsafe makes untrusted text safe to write to an interactive
// terminal. Scanned file content, file names, share names and recovered
// values can contain control characters that a terminal executes instead of
// displaying: escape sequences that clear the screen, move the cursor or
// switch to the line-drawing character set, backspaces, carriage returns and
// bidirectional overrides. Text replaces each of them with a visible, inert
// placeholder so the evidence stays readable and the display stays intact.
//
// It is for display only. Stored evidence, reports and exports keep the exact
// original bytes.
package termsafe

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// tabSpaces replaces a tab, whose display width depends on the terminal's tab
// stops and therefore cannot be measured by layout code.
const tabSpaces = "    "

// Text returns s with terminal control characters replaced by visible
// placeholders: C0 controls and DEL become Unicode control pictures (ESC is
// shown as "␛"), C1 controls and invisible formatting or bidirectional
// characters become "<U+XXXX>", tabs become spaces and invalid UTF-8 becomes
// U+FFFD. Newlines are kept. Text that needs no change is returned as is.
func Text(s string) string {
	if !needsReplacement(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for index := 0; index < len(s); {
		r, size := utf8.DecodeRuneInString(s[index:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
			index++
			continue
		}
		index += size
		switch {
		case r == '\n':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString(tabSpaces)
		case r < 0x20:
			b.WriteRune(0x2400 + r)
		case r == 0x7f:
			b.WriteRune('␡')
		case invisibleOrControl(r):
			fmt.Fprintf(&b, "<U+%04X>", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsReplacement(s string) bool {
	for index := 0; index < len(s); {
		r, size := utf8.DecodeRuneInString(s[index:])
		if r == utf8.RuneError && size == 1 {
			return true
		}
		index += size
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f || invisibleOrControl(r) {
			return true
		}
	}
	return false
}

// invisibleOrControl reports C1 controls (a terminal may treat U+009B as a
// control sequence introducer), bidirectional controls that reorder displayed
// text, zero-width characters and line or paragraph separators.
func invisibleOrControl(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0xfeff:
		return true
	case r >= 0x200b && r <= 0x200f:
		return true
	case r >= 0x2028 && r <= 0x202e:
		return true
	case r >= 0x2060 && r <= 0x2069:
		return true
	default:
		return false
	}
}

// Lines applies Text to every element.
func Lines(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = Text(value)
	}
	return out
}

// Finding returns a display copy of f with every free-text field made safe.
// Identifiers used for lookups (rule IDs, fingerprints) are left unchanged.
func Finding(f scanner.Finding) scanner.Finding {
	f.RuleName = Text(f.RuleName)
	f.Category = Text(f.Category)
	f.FilePath = Text(f.FilePath)
	f.Share = Text(f.Share)
	f.ShareDescription = Text(f.ShareDescription)
	f.ShareType = Text(f.ShareType)
	f.Host = Text(f.Host)
	f.Source = Text(f.Source)
	f.ArchivePath = Text(f.ArchivePath)
	f.ArchiveMemberPath = Text(f.ArchiveMemberPath)
	f.DatabaseFilePath = Text(f.DatabaseFilePath)
	f.DatabaseTable = Text(f.DatabaseTable)
	f.DatabaseColumn = Text(f.DatabaseColumn)
	f.DatabaseRowContext = Text(f.DatabaseRowContext)
	f.DFSNamespacePath = Text(f.DFSNamespacePath)
	f.DFSLinkPath = Text(f.DFSLinkPath)
	f.Match = Text(f.Match)
	f.MatchedText = Text(f.MatchedText)
	f.MatchedTextRedacted = Text(f.MatchedTextRedacted)
	f.Snippet = Text(f.Snippet)
	f.Context = Text(f.Context)
	f.ContextRedacted = Text(f.ContextRedacted)
	f.PotentialAccount = Text(f.PotentialAccount)
	f.MatchReason = Text(f.MatchReason)
	f.RuleExplanation = Text(f.RuleExplanation)
	f.RuleRemediation = Text(f.RuleRemediation)
	f.PriorityReason = Text(f.PriorityReason)
	f.SharePriorityReason = Text(f.SharePriorityReason)
	f.ConfidenceReasons = Lines(f.ConfidenceReasons)
	if len(f.SupportingSignals) > 0 {
		signals := make([]scanner.SupportingSignal, len(f.SupportingSignals))
		copy(signals, f.SupportingSignals)
		for index := range signals {
			signals[index].RuleName = Text(signals[index].RuleName)
			signals[index].Match = Text(signals[index].Match)
			signals[index].Reason = Text(signals[index].Reason)
		}
		f.SupportingSignals = signals
	}
	return f
}

// Candidate returns a display copy of a credential candidate with its
// free-text fields made safe.
func Candidate(c credentialanalysis.Candidate) credentialanalysis.Candidate {
	c.Identity = Text(c.Identity)
	c.Domain = Text(c.Domain)
	c.Value = Text(c.Value)
	c.Host = Text(c.Host)
	c.Share = Text(c.Share)
	c.Path = Text(c.Path)
	c.Container = Text(c.Container)
	c.Source = Text(c.Source)
	c.ValidationBasis = Text(c.ValidationBasis)
	c.ReviewReasons = Lines(c.ReviewReasons)
	if len(c.Evidence) > 0 {
		evidence := make([]credentialanalysis.Evidence, len(c.Evidence))
		copy(evidence, c.Evidence)
		for index := range evidence {
			evidence[index].Source = Text(evidence[index].Source)
			evidence[index].Path = Text(evidence[index].Path)
			evidence[index].Location = Text(evidence[index].Location)
		}
		c.Evidence = evidence
	}
	return c
}

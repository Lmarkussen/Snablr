package termsafe

import (
	"strings"
	"testing"

	"snablr/internal/scanner"
)

func TestTextNeutralisesTerminalControls(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain ascii © → æøå 日本", "plain ascii © → æøå 日本"},
		{"line1\nline2", "line1\nline2"},
		{"\x1b[2J\x1b[Hboom", "␛[2J␛[Hboom"},
		{"\x1b(0lqqk\x1b(B", "␛(0lqqk␛(B"},
		{"\x1b]0;title\x07", "␛]0;title␇"},
		{"a\tb", "a    b"},
		{"a\rb", "a␍b"},
		{"x\by", "x␈y"},
		{"nul\x00", "nul␀"},
		{"del\x7f", "del␡"},
		{"\u009b2J", "<U+009B>2J"},
		{"a\u202eevil", "a<U+202E>evil"},
		{"zero\u200bwidth", "zero<U+200B>width"},
		{"bom\ufeff", "bom<U+FEFF>"},
		{"bad\xffutf8", "bad�utf8"},
	}
	for _, tc := range cases {
		if got := Text(tc.in); got != tc.want {
			t.Errorf("Text(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTextOutputHasNoTerminalControls(t *testing.T) {
	hostile := "\x1b[2J\x1b[H\x1b(0\x1b]0;x\x07\u009b31m\t\r\x08\u202e\u2028\x00\x7f\xff"
	out := Text(hostile)
	for _, r := range out {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x2028 {
			t.Fatalf("control rune %U survived in %q", r, out)
		}
	}
}

func TestTextReturnsCleanInputUnchanged(t *testing.T) {
	clean := strings.Repeat("evidence æøå → ok\n", 10)
	if Text(clean) != clean {
		t.Fatal("clean text was modified")
	}
}

func TestFindingIsADisplayCopy(t *testing.T) {
	original := scanner.Finding{RuleID: "rule.\x1bid", FilePath: "dir/\x1b[2Jfile", MatchedText: "user\x1b(0", SupportingSignals: []scanner.SupportingSignal{{Match: "\x1b[31m"}}}
	safe := Finding(original)
	if safe.FilePath != "dir/␛[2Jfile" || safe.MatchedText != "user␛(0" || safe.SupportingSignals[0].Match != "␛[31m" {
		t.Fatalf("display copy not sanitised: %+v", safe)
	}
	if safe.RuleID != original.RuleID {
		t.Fatal("rule identifier must stay exact for lookups")
	}
	if original.FilePath != "dir/\x1b[2Jfile" || original.SupportingSignals[0].Match != "\x1b[31m" {
		t.Fatal("original finding was modified; stored evidence must stay exact")
	}
}

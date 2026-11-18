package textdecode

import "testing"

func TestStripTerminalSequences(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain æøå © → text", "plain æøå © → text"},
		{"password=\x1b[1mSynthetic-1!\x1b[0m", "password=Synthetic-1!"},
		{"\x1b[38;5;196musername=svc\x1b[0m", "username=svc"},
		{"\x1b[2J\x1b[Hclear", "clear"},
		{"\x1b]0;window title\x07after", "after"},
		{"\x1b]8;;http://synthetic\x1b\\link\x1b]8;;\x1b\\", "link"},
		{"\x1b(0lqqk\x1b(B", "lqqk"},
		{"\u009b31mred\u009b0m", "red"},
		{"bell\x07", "bell"},
		{"line1\nline2\r\n", "line1\nline2\r\n"},
		{"\x1b]0;unterminated\nnext line", "\nnext line"},
		{"\x1b[", ""},
		{"\x1b[12\nkept", "\nkept"},
	}
	for _, tc := range cases {
		if got := StripTerminalSequences(tc.in); got != tc.want {
			t.Errorf("StripTerminalSequences(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Escape-heavy console output is text; its escape bytes previously pushed it
// below the printable threshold so it was not decoded at all.
func TestDecodeTreatsTerminalColouredOutputAsText(t *testing.T) {
	var content []byte
	for i := 0; i < 20; i++ {
		content = append(content, []byte("\x1b[1;32m[ OK ]\x1b[0m \x1b[36mstep\x1b[0m\n")...)
	}
	content = append(content, []byte("password=\x1b[1mSynthetic-Decode-5!\x1b[0m\n")...)
	text, ok := Decode(content)
	if !ok {
		t.Fatal("coloured console output was not decoded as text")
	}
	if want := "password=Synthetic-Decode-5!\n"; len(text) < len(want) || text[len(text)-len(want):] != want {
		t.Fatalf("decoded text not stripped of terminal sequences: %q", text)
	}
}

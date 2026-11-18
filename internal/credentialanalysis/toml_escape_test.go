package credentialanalysis

import "testing"

// TOML basic strings use escapes; the identity in a "DOMAIN\\user" value is
// DOMAIN\user. Literal strings keep backslashes verbatim.
func TestHarvestTOMLDecodesBasicStringEscapes(t *testing.T) {
	cases := []struct {
		name, content, identity, value string
	}{
		{"basic string", "[service]\nlogin = \"SYNTHETIC\\\\deploy627\"\npasswd = \"Velvet-457-Delta!\"\n", `SYNTHETIC\deploy627`, "Velvet-457-Delta!"},
		{"literal string", "[service]\nlogin = 'SYNTHETIC\\deploy627'\npasswd = 'Velvet-457-Delta!'\n", `SYNTHETIC\deploy627`, "Velvet-457-Delta!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, candidate := range Harvest(HarvestInput{Path: "app.toml", Content: []byte(tc.content)}) {
				if candidate.Identity == tc.identity && candidate.Value == tc.value {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected pair %q/%q from TOML %s", tc.identity, tc.value, tc.name)
			}
		})
	}
}

package credentialanalysis

import "testing"

func sameLinePairs(t *testing.T, path, content string) []Candidate {
	t.Helper()
	var pairs []Candidate
	for _, candidate := range Harvest(HarvestInput{Path: path, Content: []byte(content)}) {
		if candidate.ValidationBasis == "explicit same-line credential fields" {
			pairs = append(pairs, candidate)
		}
	}
	return pairs
}

// An identity field followed by a password field on one line was previously
// not harvested in any format, although the same fields on separate lines
// produced a confirmed pair.
func TestHarvestSameLineCredentialPairs(t *testing.T) {
	cases := []struct {
		name, path, content string
		identity, value     string
	}{
		{"space separated", "notes.txt", "account=svc_synthetic password=Harbor-811-Seven!\n", "svc_synthetic", "Harbor-811-Seven!"},
		{"colon and semicolon", "notes.txt", "user: svc_synthetic; pwd: Synthetic#42\n", "svc_synthetic", "Synthetic#42"},
		// Spaced passwords stay subject to the shared prose value-shape filter.
		{"quoted values", "deploy.cfg", `username="svc synthetic" password="Quoted-Synthetic#3"` + "\n", "svc synthetic", "Quoted-Synthetic#3"},
		{"norwegian labels", "notater.txt", "brukernavn=ola.synthetic passord=Hemmelig-Syntetisk-7\n", "ola.synthetic", "Hemmelig-Syntetisk-7"},
		{"separators kept inside password", "notes.txt", "user=svc_synthetic password=Pa,ss;word9\n", "svc_synthetic", "Pa,ss;word9"},
		{"keyword connection style", "pg.txt", "host=db.synthetic user=svc_synthetic password=Pg-Synthetic-1\n", "svc_synthetic", "Pg-Synthetic-1"},
		{"followed by another field", "notes.txt", "login=svc_synthetic, password=Synthetic-55, host=app.synthetic\n", "svc_synthetic", "Synthetic-55"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pairs := sameLinePairs(t, tc.path, tc.content)
			if len(pairs) != 1 {
				t.Fatalf("pairs=%d, want 1: %#v", len(pairs), pairs)
			}
			if pairs[0].Identity != tc.identity || pairs[0].Value != tc.value || pairs[0].Verification != Confirmed {
				t.Fatalf("got identity=%q value=%q verification=%s, want %q/%q confirmed", pairs[0].Identity, pairs[0].Value, pairs[0].Verification, tc.identity, tc.value)
			}
		})
	}
}

func TestHarvestSameLinePairsRejectsNonPairs(t *testing.T) {
	cases := []struct{ name, content string }{
		{"placeholder password", "username=svc_synthetic password=CHANGE_ME\n"},
		{"unresolved variable", "user=svc_synthetic password=${DEPLOY_PASSWORD}\n"},
		{"masked password", "user=svc_synthetic password=********\n"},
		{"fields not adjacent", "user=svc_synthetic note=rotated password=Synthetic-9\n"},
		{"password before identity", "password=Synthetic-9 user=svc_synthetic\n"},
		{"incompatible scopes", "db_user=svc_synthetic api_password=Synthetic-9\n"},
		{"prose", "Password policy: choose a strong password and never share it.\n"},
		{"single field", "password=Synthetic-9\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if pairs := sameLinePairs(t, "notes.txt", tc.content); len(pairs) != 0 {
				t.Fatalf("unexpected same-line pairs: %#v", pairs)
			}
		})
	}
}

package discovery

import (
	"reflect"
	"testing"
)

func TestBindCandidatesBareUsername(t *testing.T) {
	t.Parallel()

	got := bindCandidates("snaffleuser", "evilhaxxor.local")
	want := []bindCandidate{
		{Label: "username", Value: "snaffleuser"},
		{Label: "UPN", Value: "snaffleuser@evilhaxxor.local"},
		{Label: "DOMAIN\\USER", Value: `EVILHAXXOR\snaffleuser`},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestBindCandidatesExplicitFormatsRemainSingleAttempt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		username string
		want     []bindCandidate
	}{
		{
			name:     "explicit upn",
			username: "snaffleuser@evilhaxxor.local",
			want: []bindCandidate{{
				Label: "explicit UPN",
				Value: "snaffleuser@evilhaxxor.local",
			}},
		},
		{
			name:     "explicit down-level",
			username: `EVILHAXXOR\snaffleuser`,
			want: []bindCandidate{{
				Label: "explicit DOMAIN\\USER",
				Value: `EVILHAXXOR\snaffleuser`,
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := bindCandidates(tc.username, "evilhaxxor.local"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}

func TestBindCandidatesWithoutDomain(t *testing.T) {
	t.Parallel()

	got := bindCandidates("snaffleuser", "")
	want := []bindCandidate{{
		Label: "username",
		Value: "snaffleuser",
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDownLevelBindDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"evilhaxxor.local": "EVILHAXXOR",
		"EXAMPLE":          "EXAMPLE",
		"":                 "",
	}

	for input, want := range cases {
		if got := downLevelBindDomain(input); got != want {
			t.Fatalf("downLevelBindDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDomainFromNamingContext(t *testing.T) {
	t.Parallel()

	got := domainFromNamingContext("DC=evilhaxxor,DC=local")
	if got != "evilhaxxor.local" {
		t.Fatalf("domainFromNamingContext returned %q", got)
	}
}

func TestNormalizeDetectedDomainRejectsPlaceholderValues(t *testing.T) {
	t.Parallel()

	cases := []string{"(none)", "none", "(invalid)"}
	for _, input := range cases {
		if got := normalizeDetectedDomain(input); got != "" {
			t.Fatalf("normalizeDetectedDomain(%q) = %q, want empty", input, got)
		}
	}
}

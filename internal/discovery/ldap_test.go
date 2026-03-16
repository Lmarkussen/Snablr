package discovery

import (
	"reflect"
	"testing"
)

func TestBindCandidatesBareUsername(t *testing.T) {
	t.Parallel()

	got := bindCandidates("test_operator", "synthetic.example.test")
	want := []bindCandidate{
		{Label: "username", Value: "test_operator"},
		{Label: "UPN", Value: "test_operator@synthetic.example.test"},
		{Label: "DOMAIN\\USER", Value: `synthetic_domain\test_operator`},
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
			username: "test_operator@synthetic.example.test",
			want: []bindCandidate{{
				Label: "explicit UPN",
				Value: "test_operator@synthetic.example.test",
			}},
		},
		{
			name:     "explicit down-level",
			username: `synthetic_domain\test_operator`,
			want: []bindCandidate{{
				Label: "explicit DOMAIN\\USER",
				Value: `synthetic_domain\test_operator`,
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := bindCandidates(tc.username, "synthetic.example.test"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}

func TestBindCandidatesWithoutDomain(t *testing.T) {
	t.Parallel()

	got := bindCandidates("test_operator", "")
	want := []bindCandidate{{
		Label: "username",
		Value: "test_operator",
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDownLevelBindDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"synthetic.example.test": "synthetic_domain",
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

	got := domainFromNamingContext("DC=synthetic_domain,DC=local")
	if got != "synthetic.example.test" {
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

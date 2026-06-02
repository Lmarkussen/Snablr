package discovery

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestBindCandidatesBareUsername(t *testing.T) {
	t.Parallel()

	got := bindCandidates("testuser", "TEST.LOCAL")
	want := []bindCandidate{
		{Label: "username", Value: "testuser"},
		{Label: "UPN", Value: "testuser@test.local"},
		{Label: "DOMAIN\\USER", Value: `TEST\testuser`},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestNormalizeAuthModeDefaultsToPassword(t *testing.T) {
	t.Parallel()

	if got := normalizeAuthMode(""); got != AuthModePassword {
		t.Fatalf("normalizeAuthMode empty = %q, want %q", got, AuthModePassword)
	}
	if got := normalizeAuthMode(" Kerberos "); got != AuthModeKerberos {
		t.Fatalf("normalizeAuthMode kerberos = %q, want %q", got, AuthModeKerberos)
	}
}

func TestResolveKerberosCCacheRequiresCache(t *testing.T) {
	t.Setenv("KRB5CCNAME", "")

	if _, err := resolveKerberosCCache(""); err == nil {
		t.Fatal("expected missing kerberos ccache to fail")
	}
}

func TestResolveKerberosCCacheAcceptsFilePrefix(t *testing.T) {
	t.Parallel()

	got, err := resolveKerberosCCache("FILE:test.ccache")
	if err != nil {
		t.Fatalf("resolveKerberosCCache returned error: %v", err)
	}
	if got != "test.ccache" {
		t.Fatalf("resolveKerberosCCache returned %q", got)
	}
}

func TestResolveKerberosCCacheRejectsUnsupportedType(t *testing.T) {
	t.Parallel()

	if _, err := resolveKerberosCCache("DIR:test.ccache"); err == nil {
		t.Fatal("expected unsupported ccache type to fail")
	}
}

func TestResolveLDAPSPNDefaultsFromHostname(t *testing.T) {
	t.Parallel()

	got, err := resolveLDAPSPN("DC01.TEST.LOCAL", "")
	if err != nil {
		t.Fatalf("resolveLDAPSPN returned error: %v", err)
	}
	if got != "ldap/dc01.test.local" {
		t.Fatalf("resolveLDAPSPN returned %q", got)
	}
}

func TestResolveLDAPSPNRequiresOverrideForIPDomainController(t *testing.T) {
	t.Parallel()

	dc := net.IPv4(0xc0, 0x00, 0x02, 0x0a).String()
	if _, err := resolveLDAPSPN(dc, ""); err == nil {
		t.Fatal("expected IP domain controller without ldap SPN to fail")
	}

	got, err := resolveLDAPSPN(dc, "ldap/DC01.TEST.LOCAL")
	if err != nil {
		t.Fatalf("resolveLDAPSPN with override returned error: %v", err)
	}
	if got != "ldap/DC01.TEST.LOCAL" {
		t.Fatalf("resolveLDAPSPN override returned %q", got)
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
			username: "testuser@TEST.LOCAL",
			want: []bindCandidate{{
				Label: "explicit UPN",
				Value: "testuser@TEST.LOCAL",
			}},
		},
		{
			name:     "explicit down-level",
			username: `TEST\testuser`,
			want: []bindCandidate{{
				Label: "explicit DOMAIN\\USER",
				Value: `TEST\testuser`,
			}},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := bindCandidates(tc.username, "TEST.LOCAL"); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", tc.want, got)
			}
		})
	}
}

func TestBindCandidatesWithoutDomain(t *testing.T) {
	t.Parallel()

	got := bindCandidates("testuser", "")
	want := []bindCandidate{{
		Label: "username",
		Value: "testuser",
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected bind candidates:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestDownLevelBindDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"TEST.LOCAL": "TEST",
		"TEST":       "TEST",
		"":           "",
	}

	for input, want := range cases {
		if got := downLevelBindDomain(input); got != want {
			t.Fatalf("downLevelBindDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDomainFromNamingContext(t *testing.T) {
	t.Parallel()

	got := domainFromNamingContext("DC=TEST,DC=LOCAL")
	if got != "test.local" {
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

func TestRequiresLDAPSigning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ldap strong auth required",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultStrongAuthRequired,
				Err:        fmt.Errorf("bind rejected"),
			},
			want: true,
		},
		{
			name: "ldap confidentiality required",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultConfidentialityRequired,
				Err:        fmt.Errorf("bind rejected"),
			},
			want: true,
		},
		{
			name: "string stronger auth required",
			err:  fmt.Errorf("00002028: LdapErr: DSID-0C090274, comment: The server requires binds to turn on integrity checking if SSL/TLS are not already active on the connection, data 0, v4563 strongerAuthRequired"),
			want: true,
		},
		{
			name: "invalid credentials",
			err: &ldap.Error{
				ResultCode: ldap.LDAPResultInvalidCredentials,
				Err:        fmt.Errorf("bad password"),
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := requiresLDAPSigning(tc.err); got != tc.want {
				t.Fatalf("requiresLDAPSigning(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestLDAPAddressUsesCorrectDefaultPorts(t *testing.T) {
	t.Parallel()

	testHost := net.IPv4(0xc0, 0x00, 0x02, 0x14).String()
	cases := []struct {
		name        string
		input       string
		defaultPort int
		wantAddr    string
		wantHost    string
	}{
		{
			name:        "ldap default port",
			input:       testHost,
			defaultPort: defaultLDAPPort,
			wantAddr:    net.JoinHostPort(testHost, "389"),
			wantHost:    testHost,
		},
		{
			name:        "ldaps default port",
			input:       testHost,
			defaultPort: defaultLDAPSPort,
			wantAddr:    net.JoinHostPort(testHost, "636"),
			wantHost:    testHost,
		},
		{
			name:        "preserve explicit port",
			input:       net.JoinHostPort(testHost, "1636"),
			defaultPort: defaultLDAPSPort,
			wantAddr:    net.JoinHostPort(testHost, "1636"),
			wantHost:    testHost,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotAddr, gotHost := ldapAddress(tc.input, tc.defaultPort)
			if gotAddr != tc.wantAddr || gotHost != tc.wantHost {
				t.Fatalf("ldapAddress(%q, %d) = (%q, %q), want (%q, %q)", tc.input, tc.defaultPort, gotAddr, gotHost, tc.wantAddr, tc.wantHost)
			}
		})
	}
}

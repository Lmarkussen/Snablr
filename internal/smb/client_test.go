package smb

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParseNTHash(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"0123456789abcdef0123456789abcdef",
		"0123456789ABCDEF0123456789ABCDEF",
	} {
		got, err := ParseNTHash(input)
		if err != nil {
			t.Fatalf("ParseNTHash returned error: %v", err)
		}
		if got[0] != 0x01 || got[15] != 0xef {
			t.Fatalf("ParseNTHash decoded unexpected bytes")
		}
	}
}

func TestParseNTHashRejectsMalformedInputWithoutEchoingIt(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", strings.Repeat("0", 31), strings.Repeat("0", 33), strings.Repeat("g", 32), " 0123456789abcdef0123456789abcdef"} {
		_, err := ParseNTHash(input)
		if err == nil {
			t.Fatalf("ParseNTHash(%q) unexpectedly succeeded", input)
		}
		if strings.Contains(err.Error(), input) && input != "" {
			t.Fatalf("parse error echoed secret input")
		}
	}
}

func TestNewAuthModesKeepSecretsSeparate(t *testing.T) {
	t.Parallel()

	password := NewPasswordAuth(`DOMAIN\user`, "", "secret")
	if password.Mode != AuthModePassword || password.Password != "secret" || password.NTHash != [16]byte{} {
		t.Fatalf("unexpected password auth shape")
	}
	hashAuth, err := NewNTHashAuth("user", "DOMAIN", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewNTHashAuth returned error: %v", err)
	}
	if hashAuth.Mode != AuthModeNTHash || hashAuth.Password != "" || hashAuth.NTHash == [16]byte{} {
		t.Fatalf("unexpected NT hash auth shape")
	}
	passwordInitiator := newNTLMInitiator(password, "user", "DOMAIN")
	if passwordInitiator.Password != "secret" || passwordInitiator.Hash != nil {
		t.Fatalf("password mode selected the wrong NTLM credential field")
	}
	hashInitiator := newNTLMInitiator(hashAuth, "user", "DOMAIN")
	if hashInitiator.Password != "" || len(hashInitiator.Hash) != 16 {
		t.Fatalf("NT hash mode selected the wrong NTLM credential field")
	}
}

func TestSplitUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input, domain, user string
	}{
		{`DOMAIN\user`, "DOMAIN", "user"},
		{"user@domain.example", "domain.example", "user"},
		{"user", "", "user"},
	}
	for _, tt := range tests {
		domain, user := splitUser(tt.input)
		if domain != tt.domain || user != tt.user {
			t.Errorf("splitUser(%q) = (%q, %q), want (%q, %q)", tt.input, domain, user, tt.domain, tt.user)
		}
	}
}

func TestIsIgnorableCloseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "net err closed", err: net.ErrClosed, want: true},
		{name: "closed network connection", err: errors.New("write tcp 127.0.0.1:445->127.0.0.1:40000: use of closed network connection"), want: true},
		{name: "already closed", err: errors.New("connection already closed"), want: true},
		{name: "real error", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isIgnorableCloseError(tt.err); got != tt.want {
				t.Fatalf("isIgnorableCloseError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

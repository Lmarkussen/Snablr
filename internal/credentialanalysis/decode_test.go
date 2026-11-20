package credentialanalysis

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// The encoders below follow each format's published description and are
// independent of the decoders under test.

func utf16LE(text string) []byte {
	var out []byte
	for _, unit := range utf16.Encode([]rune(text)) {
		out = append(out, byte(unit), byte(unit>>8))
	}
	return out
}

func encryptGPP(t *testing.T, plain []byte, pkcs7 bool) string {
	t.Helper()
	if pkcs7 {
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	} else {
		for len(plain)%aes.BlockSize != 0 {
			plain = append(plain, ' ')
		}
	}
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(out, plain)
	return strings.TrimRight(base64.StdEncoding.EncodeToString(out), "=")
}

// encryptWinSCP follows WinSCP's EncryptPassword: flag, internal marker,
// length, shift, shift filler bytes, then key+password, each byte stored as
// hex of ^(b ^ 0xA3).
func encryptWinSCP(host, user, password string, shift int) string {
	var b strings.Builder
	put := func(c byte) { fmt.Fprintf(&b, "%02X", ^c^winSCPMagic) }
	payload := user + host + password
	put(winSCPFlag)
	put(0)
	put(byte(len(payload)))
	put(byte(shift))
	for i := 0; i < shift; i++ {
		put(byte(0x30 + i))
	}
	for i := 0; i < len(payload); i++ {
		put(payload[i])
	}
	return b.String()
}

func encryptMRemoteNGGCM(t *testing.T, password, plain string, iterations int) string {
	t.Helper()
	salt := bytes.Repeat([]byte{0x11}, 16)
	nonce := bytes.Repeat([]byte{0x22}, 16)
	key, err := pbkdf2.Key(sha1.New, password, salt, iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plain), salt)
	return base64.StdEncoding.EncodeToString(append(append(append([]byte{}, salt...), nonce...), sealed...))
}

func encryptMRemoteNGCBC(t *testing.T, plain string) string {
	t.Helper()
	key := md5.Sum([]byte("mR3m"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(plain)
	pad := aes.BlockSize - len(data)%aes.BlockSize
	data = append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
	iv := bytes.Repeat([]byte{0x33}, aes.BlockSize)
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return base64.StdEncoding.EncodeToString(append(iv, out...))
}

func TestDecodeGPPPassword(t *testing.T) {
	cases := []struct {
		name, cpassword, want string
		ok                    bool
	}{
		{"windows UTF-16LE", encryptGPP(t, utf16LE("Gpp-Synth-Pass-1"), true), "Gpp-Synth-Pass-1", true},
		{"ASCII padded with spaces", encryptGPP(t, []byte("Ascii-Synth-Pass-2!"), false), "Ascii-Synth-Pass-2!", true},
		{"not base64", "AQAAAINVALID-SYNTHETIC-CPASSWORD-0000", "", false},
		{"empty", "", "", false},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short")), "", false},
	}
	for _, tc := range cases {
		got, ok := DecodeGPPPassword(tc.cpassword)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecodeUnattendPassword(t *testing.T) {
	encode := func(text string) string { return base64.StdEncoding.EncodeToString(utf16LE(text)) }
	if got, ok := DecodeUnattendPassword(encode("Admin-Synth-4AdministratorPassword"), "AdministratorPassword"); !ok || got != "Admin-Synth-4" {
		t.Errorf("AdministratorPassword: got %q, %v", got, ok)
	}
	if got, ok := DecodeUnattendPassword(encode("Logon-Synth-3Password"), "Password"); !ok || got != "Logon-Synth-3" {
		t.Errorf("Password: got %q, %v", got, ok)
	}
	for name, value := range map[string]string{
		"suffix of another element": encode("Logon-Synth-3Password"),
		"suffix only":               encode("AdministratorPassword"),
		"not UTF-16":                base64.StdEncoding.EncodeToString([]byte("not-a-valid-unattend")),
	} {
		if got, ok := DecodeUnattendPassword(value, "AdministratorPassword"); ok {
			t.Errorf("%s decoded to %q", name, got)
		}
	}
}

func TestDecodeWinSCPPassword(t *testing.T) {
	encoded := encryptWinSCP("files.corp.example", "svc_sftp", "Sftp-Synth-Pass-5", 3)
	if got, ok := DecodeWinSCPPassword("files.corp.example", "svc_sftp", encoded); !ok || got != "Sftp-Synth-Pass-5" {
		t.Errorf("got %q, %v", got, ok)
	}
	if got, ok := DecodeWinSCPPassword("other.corp.example", "svc_sftp", encoded); ok {
		t.Errorf("decoded with the wrong host: %q", got)
	}
	if got, ok := DecodeWinSCPPassword("files.corp.example", "svc_sftp", "A35C455A1D6E6D6E6F6F6E6D3B323D3B2E7A6F6C696D"); ok {
		t.Errorf("garbage decoded to %q", got)
	}
}

func TestDecodeFileZillaPassword(t *testing.T) {
	if got, ok := DecodeFileZillaPassword(base64.StdEncoding.EncodeToString([]byte("Ftp-Synth-Pass-6"))); !ok || got != "Ftp-Synth-Pass-6" {
		t.Errorf("got %q, %v", got, ok)
	}
	if _, ok := DecodeFileZillaPassword("not base64!"); ok {
		t.Error("invalid base64 decoded")
	}
}

func TestDecodeMRemoteNGPassword(t *testing.T) {
	if got, ok := DecodeMRemoteNGPassword(encryptMRemoteNGGCM(t, "mR3m", "Rdp-Synth-Pass-7", 1000), true, 1000); !ok || got != "Rdp-Synth-Pass-7" {
		t.Errorf("GCM default key: got %q, %v", got, ok)
	}
	if got, ok := DecodeMRemoteNGPassword(encryptMRemoteNGGCM(t, "mR3m", "Rdp-Synth-Pass-8", 10000), true, 10000); !ok || got != "Rdp-Synth-Pass-8" {
		t.Errorf("GCM custom iterations: got %q, %v", got, ok)
	}
	if got, ok := DecodeMRemoteNGPassword(encryptMRemoteNGGCM(t, "Custom-Master-Synth", "Rdp-Synth-Pass-9", 1000), true, 1000); ok {
		t.Errorf("custom master password decrypted: %q", got)
	}
	if got, ok := DecodeMRemoteNGPassword(encryptMRemoteNGCBC(t, "Rdp-Synth-Pass-10"), false, 0); !ok || got != "Rdp-Synth-Pass-10" {
		t.Errorf("CBC default key: got %q, %v", got, ok)
	}
}

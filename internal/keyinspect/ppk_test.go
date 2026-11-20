package keyinspect

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// PPKFixture writes a PuTTY key file as described in the PuTTY manual
// (appendix C): format 2 MACs with HMAC-SHA1 keyed by SHA-1 of
// "putty-private-key-file-mac-key", format 3 without encryption with
// HMAC-SHA-256 and an empty key.
func ppkFixture(version int, encryption string, public, private []byte) string {
	sshString := func(b []byte) []byte {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(b)))
		return append(size[:], b...)
	}
	const algorithm, comment = "ssh-ed25519", "deploy@build-synthetic"
	var data []byte
	for _, part := range [][]byte{[]byte(algorithm), []byte(encryption), []byte(comment), public, private} {
		data = append(data, sshString(part)...)
	}
	var mac []byte
	if version == 2 {
		key := sha1.Sum([]byte("putty-private-key-file-mac-key"))
		h := hmac.New(sha1.New, key[:])
		h.Write(data)
		mac = h.Sum(nil)
	} else {
		h := hmac.New(sha256.New, nil)
		h.Write(data)
		mac = h.Sum(nil)
	}
	lines := func(b []byte) []string {
		encoded := base64.StdEncoding.EncodeToString(b)
		var out []string
		for len(encoded) > 64 {
			out = append(out, encoded[:64])
			encoded = encoded[64:]
		}
		return append(out, encoded)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PuTTY-User-Key-File-%d: %s\r\nEncryption: %s\r\nComment: %s\r\n", version, algorithm, encryption, comment)
	pub := lines(public)
	fmt.Fprintf(&b, "Public-Lines: %d\r\n%s\r\n", len(pub), strings.Join(pub, "\r\n"))
	if version == 3 && encryption != "none" {
		b.WriteString("Key-Derivation: Argon2id\r\nArgon2-Memory: 8192\r\nArgon2-Passes: 13\r\nArgon2-Parallelism: 1\r\nArgon2-Salt: 0123456789abcdef0123456789abcdef\r\n")
	}
	priv := lines(private)
	fmt.Fprintf(&b, "Private-Lines: %d\r\n%s\r\nPrivate-MAC: %s\r\n", len(priv), strings.Join(priv, "\r\n"), hex.EncodeToString(mac))
	return b.String()
}

func TestInspectorValidatesPuTTYKeys(t *testing.T) {
	public := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), bytes.Repeat([]byte{7}, 32)...)
	private := append([]byte("\x00\x00\x00\x20"), bytes.Repeat([]byte{9}, 32)...)
	cases := []struct {
		name, content, status string
		encrypted, found      bool
	}{
		{"format 3 unencrypted", ppkFixture(3, "none", public, private), StatusConfirmed, false, true},
		{"format 2 unencrypted", ppkFixture(2, "none", public, private), StatusConfirmed, false, true},
		{"format 3 encrypted", ppkFixture(3, "aes256-cbc", public, bytes.Repeat([]byte{5}, 48)), StatusEncrypted, true, true},
		{"format 2 encrypted", ppkFixture(2, "aes256-cbc", public, bytes.Repeat([]byte{5}, 48)), StatusEncrypted, true, true},
		{"tampered MAC", strings.Replace(ppkFixture(3, "none", public, private), "Private-MAC: ", "Private-MAC: 00", 1), "", false, false},
		{"no MAC line", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: synthetic\nPublic-Lines: 1\nAAAAC3NzaC1lZDI1NTE5\nPrivate-Lines: 1\nAAAAIHN5bnRoZXRpYw==\n", "", false, false},
	}
	for _, tc := range cases {
		matches := New().InspectContent(Candidate{Name: "deploy.ppk", Extension: ".ppk"}, []byte(tc.content))
		if !tc.found {
			if len(matches) != 0 {
				t.Errorf("%s: unverifiable key reported: %+v", tc.name, matches[0])
			}
			continue
		}
		if len(matches) != 1 {
			t.Fatalf("%s: got %d matches", tc.name, len(matches))
		}
		m := matches[0]
		if m.Status != tc.status || m.Encrypted != tc.encrypted || m.Format != "PuTTY" || m.Algorithm != "ssh-ed25519" {
			t.Errorf("%s: status=%s encrypted=%v format=%s algorithm=%s", tc.name, m.Status, m.Encrypted, m.Format, m.Algorithm)
		}
	}
	if !New().NeedsContent(Candidate{Name: "deploy.ppk", Extension: ".ppk"}) {
		t.Error(".ppk content is not requested")
	}
}

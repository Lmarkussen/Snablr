package keyinspect

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
)

const ppkHeaderPrefix = "PuTTY-User-Key-File-"

// ppkKey is a parsed PuTTY private key file (format 2 or 3).
type ppkKey struct {
	header     string
	version    int
	algorithm  string
	encryption string
	comment    string
	public     []byte
	private    []byte
	mac        []byte
}

// parsePPK reads a PuTTY .ppk file. ok is false when the text is not a
// complete format 2 or 3 key file.
func parsePPK(content []byte) (ppkKey, bool) {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(strings.TrimLeft(text, "\ufeff \t\n"), "\n")
	var key ppkKey
	field := func(index int, name string) (string, bool) {
		if index >= len(lines) {
			return "", false
		}
		prefix := name + ": "
		if !strings.HasPrefix(lines[index], prefix) {
			return "", false
		}
		return strings.TrimSpace(strings.TrimPrefix(lines[index], prefix)), true
	}
	blob := func(index int, name string) ([]byte, int, bool) {
		count, ok := field(index, name)
		if !ok {
			return nil, index, false
		}
		n, err := strconv.Atoi(count)
		if err != nil || n <= 0 || index+1+n > len(lines) {
			return nil, index, false
		}
		data, err := base64.StdEncoding.DecodeString(strings.Join(lines[index+1:index+1+n], ""))
		if err != nil {
			return nil, index, false
		}
		return data, index + 1 + n, true
	}

	first := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(first, ppkHeaderPrefix) {
		return key, false
	}
	versionText, algorithm, ok := strings.Cut(strings.TrimPrefix(first, ppkHeaderPrefix), ": ")
	if !ok {
		return key, false
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || (version != 2 && version != 3) {
		return key, false
	}
	key.header, key.version, key.algorithm = first, version, strings.TrimSpace(algorithm)
	index := 1
	if key.encryption, ok = field(index, "Encryption"); !ok {
		return key, false
	}
	index++
	if key.comment, ok = field(index, "Comment"); !ok {
		return key, false
	}
	index++
	if key.public, index, ok = blob(index, "Public-Lines"); !ok {
		return key, false
	}
	// Format 3 names the key derivation of an encrypted key before the
	// private lines.
	for index < len(lines) && !strings.HasPrefix(lines[index], "Private-Lines: ") {
		if !strings.HasPrefix(lines[index], "Key-Derivation: ") && !strings.HasPrefix(lines[index], "Argon2-") {
			return key, false
		}
		index++
	}
	if key.private, index, ok = blob(index, "Private-Lines"); !ok {
		return key, false
	}
	macText, ok := field(index, "Private-MAC")
	if !ok {
		return key, false
	}
	if key.mac, err = hex.DecodeString(macText); err != nil {
		return key, false
	}
	return key, true
}

// verifyUnencryptedPPK checks the file MAC of an unencrypted key: HMAC-SHA1
// keyed with SHA-1 of "putty-private-key-file-mac-key" for format 2, and
// HMAC-SHA-256 with an empty key for format 3.
func verifyUnencryptedPPK(key ppkKey) bool {
	var mac hash.Hash
	switch key.version {
	case 2:
		sum := sha1.Sum([]byte("putty-private-key-file-mac-key"))
		mac = hmac.New(sha1.New, sum[:])
	case 3:
		mac = hmac.New(sha256.New, nil)
	default:
		return false
	}
	var data bytes.Buffer
	for _, part := range [][]byte{[]byte(key.algorithm), []byte(key.encryption), []byte(key.comment), key.public, key.private} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		data.Write(size[:])
		data.Write(part)
	}
	mac.Write(data.Bytes())
	return hmac.Equal(mac.Sum(nil), key.mac)
}

// inspectPPK classifies a PuTTY key file: an unencrypted key whose MAC
// verifies is usable as is, an encrypted key needs its passphrase. A file
// that cannot be verified is left to the extension rule.
func inspectPPK(content []byte) (header, algorithm, status, reason string, encrypted, ok bool) {
	key, parsed := parsePPK(content)
	if !parsed {
		return "", "", "", "", false, false
	}
	if !strings.EqualFold(key.encryption, "none") {
		return key.header, key.algorithm, StatusEncrypted, "encrypted PuTTY private key (" + key.encryption + ")", true, true
	}
	if !verifyUnencryptedPPK(key) {
		return "", "", "", "", false, false
	}
	return key.header, key.algorithm, StatusConfirmed, "", false, true
}

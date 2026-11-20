package credentialanalysis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

// Remote-control tools that protect saved passwords with a fixed, published
// key: VNC servers (DES with the RFB key) and TeamViewer before 14.7
// (AES-128-CBC with the key published as CVE-2019-18988).

const (
	decodedVNCBasis        = "VNC saved password decrypted (fixed DES key)"
	decodedTeamViewerBasis = "TeamViewer saved password decrypted (published AES key, CVE-2019-18988)"
)

// vncKey is the fixed RFB password key with each byte's bits reversed, as
// DES implementations expect it.
var vncKey = []byte{0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0}

// DecodeVNCPassword decrypts an 8-byte VNC password (16 hex characters;
// UltraVNC appends a 2-character checksum, which is ignored).
func DecodeVNCPassword(hexValue string) (string, bool) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexValue))
	if err != nil || len(raw) < 8 || len(raw) > 9 {
		return "", false
	}
	block, err := des.NewCipher(vncKey)
	if err != nil {
		return "", false
	}
	plain := make([]byte, 8)
	block.Decrypt(plain, raw[:8])
	text := strings.TrimRight(string(plain), "\x00")
	if text == "" {
		return "", false
	}
	return printableText(text)
}

var (
	teamViewerKey = []byte{0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00}
	teamViewerIV  = []byte{0x01, 0x00, 0x01, 0x00, 0x67, 0x24, 0x4f, 0x43, 0x6e, 0x67, 0x62, 0xf2, 0x5e, 0xa8, 0xd7, 0x04}
)

// DecodeTeamViewerPassword decrypts a TeamViewer *PasswordAES registry
// value (UTF-16LE text, zero padded).
func DecodeTeamViewerPassword(raw []byte) (string, bool) {
	if len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", false
	}
	block, err := aes.NewCipher(teamViewerKey)
	if err != nil {
		return "", false
	}
	plain := make([]byte, len(raw))
	cipher.NewCBCDecrypter(block, teamViewerIV).CryptBlocks(plain, raw)
	if len(plain)%2 != 0 {
		return "", false
	}
	units := make([]uint16, 0, len(plain)/2)
	for i := 0; i+1 < len(plain); i += 2 {
		unit := uint16(plain[i]) | uint16(plain[i+1])<<8
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	if len(units) == 0 {
		return "", false
	}
	return printableText(string(utf16.Decode(units)))
}

// harvestUltraVNCIni decrypts passwd (full access) and passwd2 (view only)
// in an UltraVNC ultravnc.ini.
func harvestUltraVNCIni(text string, add func(Candidate)) {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section != "ultravnc" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "passwd", "passwd2":
			if plaintext, ok := DecodeVNCPassword(value); ok {
				add(Candidate{Verification: Confirmed, CredentialType: "password", Value: plaintext, ValidationBasis: decodedVNCBasis})
			}
		}
	}
}

// harvestRegistryRemoteStores decrypts VNC and TeamViewer passwords in a
// Registry Editor export.
func harvestRegistryRemoteStores(text string, add func(Candidate)) {
	for _, key := range parseRegistryExport(text) {
		path := strings.ToLower(key.path)
		switch {
		case strings.Contains(path, "vnc"):
			for _, name := range []string{"password", "passwordviewonly", "controlpassword", "passwd", "passwd2"} {
				value, ok := key.values[name]
				if !ok {
					continue
				}
				encoded := hex.EncodeToString(value.binary)
				if value.binary == nil {
					encoded = value.text
				}
				if plaintext, ok := DecodeVNCPassword(encoded); ok {
					add(Candidate{Verification: Confirmed, CredentialType: "password", Value: plaintext, ValidationBasis: decodedVNCBasis})
				}
			}
		case strings.Contains(path, "teamviewer"):
			for name, value := range key.values {
				if !strings.HasSuffix(name, "passwordaes") && name != "securitypasswordexported" {
					continue
				}
				plaintext, ok := DecodeTeamViewerPassword(value.binary)
				if !ok {
					continue
				}
				candidate := Candidate{Verification: Confirmed, CredentialType: "password", Value: plaintext, ValidationBasis: decodedTeamViewerBasis}
				if name == "proxypasswordaes" {
					candidate.Identity = strings.TrimSpace(key.values["proxyusername"].text)
				}
				add(candidate)
			}
		}
	}
}

type registryValue struct {
	text   string
	binary []byte
}

type registryKey struct {
	path   string
	values map[string]registryValue // lower-case value names
}

// parseRegistryExport reads the keys and values of a Registry Editor export
// (REGEDIT4 or version 5.00): string values and hex binary values, with
// continuation lines joined.
func parseRegistryExport(text string) []registryKey {
	var keys []registryKey
	var current *registryKey
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, `\`) + strings.TrimSpace(lines[i])
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			keys = append(keys, registryKey{path: strings.Trim(line, "[]"), values: map[string]registryValue{}})
			current = &keys[len(keys)-1]
			continue
		}
		if current == nil || !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"=`)
		if end < 0 {
			continue
		}
		name := strings.ToLower(line[1 : end+1])
		raw := strings.TrimSpace(line[end+3:])
		switch {
		case strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && len(raw) >= 2:
			// regedit escapes backslashes and quotes in string values.
			current.values[name] = registryValue{text: strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(raw[1 : len(raw)-1])}
		case strings.HasPrefix(strings.ToLower(raw), "hex:"):
			if data, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(raw[4:], ",", ""), " ", "")); err == nil {
				current.values[name] = registryValue{binary: data}
			}
		}
	}
	return keys
}

// isRegistryExport reports whether text is a Registry Editor export.
func isRegistryExport(text string) bool {
	head := strings.TrimSpace(text)
	if len(head) > 64 {
		head = head[:64]
	}
	return strings.HasPrefix(head, "Windows Registry Editor Version") || strings.HasPrefix(head, "REGEDIT4")
}

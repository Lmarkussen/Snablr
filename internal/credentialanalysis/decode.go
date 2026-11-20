package credentialanalysis

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Some products store passwords encrypted or obfuscated with a key that is
// public: the same for every installation and published by the vendor or
// long documented. Decoding them recovers the plaintext without any secret
// of the target. User-bound protection (DPAPI) and custom master passwords
// are never attempted, and nothing is cracked.

// gppKey is the AES-256 key Microsoft published for Group Policy
// Preferences cpassword values (MS-GPPREF 2.2.1.1.4).
var gppKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// DecodeGPPPassword decrypts a Group Policy Preferences cpassword value.
// Windows writes the plaintext as UTF-16LE; values written by other tools
// as plain ASCII, padded with spaces, are accepted too. ok is false for anything that does not
// decrypt to printable text.
func DecodeGPPPassword(cpassword string) (string, bool) {
	value := strings.TrimSpace(cpassword)
	if value == "" {
		return "", false
	}
	if rem := len(value) % 4; rem != 0 {
		value += strings.Repeat("=", 4-rem)
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return "", false
	}
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		return "", false
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, data)
	if unpadded, ok := stripPKCS7(plain); ok {
		plain = unpadded
	} else {
		// Values written by tools other than Windows may pad with spaces or
		// NULs instead of PKCS#7; the printable-text check still applies.
		plain = bytes.TrimRight(plain, "\x00 ")
	}
	return decodedText(plain)
}

func stripPKCS7(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(data) {
		return nil, false
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, false
		}
	}
	return data[:len(data)-pad], true
}

// decodedText turns recovered bytes into text: UTF-16LE when every high
// byte is zero (Latin text as Windows writes it), else UTF-8, else general
// UTF-16LE. The text must be printable.
func decodedText(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if len(data)%2 == 0 {
		latin := true
		for i := 1; i < len(data); i += 2 {
			if data[i] != 0 {
				latin = false
				break
			}
		}
		if latin {
			return printableText(utf16Text(data))
		}
	}
	if utf8.Valid(data) {
		if text, ok := printableText(string(data)); ok {
			return text, true
		}
	}
	if len(data)%2 == 0 {
		return printableText(utf16Text(data))
	}
	return "", false
}

func utf16Text(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
	}
	return string(utf16.Decode(units))
}

func printableText(text string) (string, bool) {
	if text == "" {
		return "", false
	}
	for _, r := range text {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return "", false
		}
	}
	return text, true
}

// gppIdentityAttributes are the Properties attributes naming the account a
// cpassword belongs to, by preference item type (Groups/Users, Scheduled
// Tasks, Services, Drives, Data Sources).
var gppIdentityAttributes = []string{"user_name", "run_as", "account_name", "username"}

// harvestGPPNode reads a Group Policy Preferences element carrying a
// cpassword attribute.
func harvestGPPNode(node *xmlHarvestNode, add func(Candidate)) {
	cpassword := strings.TrimSpace(node.attrs["cpassword"])
	if cpassword == "" {
		return
	}
	identity := ""
	for _, key := range gppIdentityAttributes {
		if value := strings.TrimSpace(node.attrs[key]); value != "" {
			identity = value
			break
		}
	}
	plaintext, ok := DecodeGPPPassword(cpassword)
	if !ok {
		add(Candidate{Verification: Review, CredentialType: "password", Identity: identity, Value: cpassword, Encrypted: true,
			ReviewReasons: []string{"GPP cpassword does not decrypt with the published key"}})
		return
	}
	candidate := Candidate{Verification: Confirmed, CredentialType: "password", Identity: identity, Value: plaintext,
		ValidationBasis: "GPP cpassword decrypted with the published key",
		Evidence:        []Evidence{{Location: "cpassword attribute"}}}
	if identity == "" || IsPlaceholderIdentity(identity) {
		candidate.Verification = Review
		candidate.Identity = ""
		candidate.ValidationBasis = ""
		candidate.ReviewReasons = []string{"decrypted GPP cpassword has no account in the same element"}
	}
	add(candidate)
}

// DecodeUnattendPassword decodes a Windows unattend password written with
// <PlainText>false</PlainText>: base64 of the UTF-16LE password followed by
// the element name ("AdministratorPassword" or "Password"). ok is false
// when the value is not in that form.
func DecodeUnattendPassword(value, element string) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(data) == 0 || len(data)%2 != 0 {
		return "", false
	}
	text, ok := printableText(utf16Text(data))
	if !ok || !strings.HasSuffix(text, element) {
		return "", false
	}
	text = strings.TrimSuffix(text, element)
	return text, text != ""
}

// Package jenkinsinspect decrypts the secrets a Jenkins controller stores in
// its home directory. Jenkins encrypts credentials.xml and job secrets with
// a key that is itself stored, encrypted with secrets/master.key, in
// secrets/hudson.util.Secret. With both files the secrets decrypt offline.
package jenkinsinspect

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var magic = []byte("::::MAGIC::::")

// SecretKey derives the key Jenkins encrypts secrets with from the contents
// of secrets/master.key and secrets/hudson.util.Secret.
func SecretKey(masterKey, hudsonSecret []byte) ([]byte, bool) {
	master := bytes.TrimSpace(masterKey)
	if len(master) == 0 || len(hudsonSecret) == 0 || len(hudsonSecret)%aes.BlockSize != 0 {
		return nil, false
	}
	digest := sha256.Sum256(master)
	plain, ok := decryptECB(digest[:16], hudsonSecret)
	if !ok {
		return nil, false
	}
	plain, ok = stripPKCS7(plain)
	if !ok || !bytes.HasSuffix(plain, magic) || len(plain)-len(magic) < 16 {
		return nil, false
	}
	return append([]byte(nil), plain[:16]...), true
}

// Decrypt decrypts a stored secret: the current "{AQAAAB...}" form
// (AES-CBC with an embedded IV) or the legacy base64 form (AES-ECB with a
// trailing magic marker).
func Decrypt(key []byte, value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(key) != 16 || value == "" {
		return "", false
	}
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		return decryptCurrent(key, value[1:len(value)-1])
	}
	return decryptLegacy(key, value)
}

func decryptCurrent(key []byte, encoded string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < 9 || raw[0] != 1 {
		return "", false
	}
	ivLength := int(binary.BigEndian.Uint32(raw[1:5]))
	dataLength := int(binary.BigEndian.Uint32(raw[5:9]))
	if ivLength != aes.BlockSize || dataLength <= 0 || dataLength%aes.BlockSize != 0 || 9+ivLength+dataLength != len(raw) {
		return "", false
	}
	iv := raw[9 : 9+ivLength]
	data := raw[9+ivLength:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)
	plain, ok := stripPKCS7(plain)
	if !ok {
		return "", false
	}
	return text(plain)
}

func decryptLegacy(key []byte, encoded string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return "", false
	}
	plain, ok := decryptECB(key, raw)
	if !ok {
		return "", false
	}
	if stripped, ok := stripPKCS7(plain); ok {
		plain = stripped
	}
	index := bytes.Index(plain, magic)
	if index < 0 {
		return "", false
	}
	return text(plain[:index])
}

func decryptECB(key, data []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil || len(data)%aes.BlockSize != 0 {
		return nil, false
	}
	plain := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(plain[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return plain, true
}

func stripPKCS7(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize || n > len(data) {
		return nil, false
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, false
		}
	}
	return data[:len(data)-n], true
}

func text(data []byte) (string, bool) {
	if len(data) == 0 || !utf8.Valid(data) {
		return "", false
	}
	return string(data), true
}

// Secret is an encrypted value in a Jenkins XML file, with the account and
// credential it belongs to.
type Secret struct {
	Field        string // element name: password, secret, privateKey, passphrase, ...
	Username     string
	CredentialID string
	Value        string // the encrypted form as stored
}

var (
	currentForm = regexp.MustCompile(`^\{AQAAAB[A-Za-z0-9+/=]{20,}\}$`)
	legacyForm  = regexp.MustCompile(`^[A-Za-z0-9+/]{22,}={0,2}$`)
)

// secretFields are the elements Jenkins and its plugins store encrypted;
// only these are tried in the legacy form, which has no marker of its own.
var secretFields = map[string]struct{}{
	"password": {}, "secret": {}, "privatekey": {}, "passphrase": {}, "apitoken": {}, "token": {},
	"secretpassphrase": {}, "privatekeypassword": {}, "secretbytes": {},
}

type node struct {
	name     string
	text     strings.Builder
	parent   *node
	children []*node
}

// Secrets lists the encrypted values in a Jenkins XML file
// (credentials.xml, config.xml, job and node configuration). Each value is
// paired with the username and id of the credential object that holds it.
func Secrets(content []byte) []Secret {
	root := parse(content)
	if root == nil {
		return nil
	}
	var out []Secret
	var walk func(*node)
	walk = func(n *node) {
		for _, child := range n.children {
			walk(child)
		}
		if len(n.children) > 0 {
			return
		}
		value := strings.TrimSpace(n.text.String())
		_, legacyField := secretFields[strings.ToLower(n.name)]
		if !currentForm.MatchString(value) && !(legacyField && legacyForm.MatchString(value)) {
			return
		}
		secret := Secret{Field: n.name, Value: value}
		// The credential object is the parent, or the grandparent for
		// nested values such as <privateKeySource><privateKey>.
		for owner, depth := n.parent, 0; owner != nil && depth < 2; owner, depth = owner.parent, depth+1 {
			for _, sibling := range owner.children {
				switch strings.ToLower(sibling.name) {
				case "username":
					if secret.Username == "" {
						secret.Username = strings.TrimSpace(sibling.text.String())
					}
				case "id":
					if secret.CredentialID == "" {
						secret.CredentialID = strings.TrimSpace(sibling.text.String())
					}
				}
			}
			if secret.Username != "" || secret.CredentialID != "" {
				break
			}
		}
		out = append(out, secret)
	}
	walk(root)
	return out
}

// xml11Declaration matches the XML 1.1 declaration Jenkins writes, which
// the decoder does not accept; the documents are valid XML 1.0 otherwise.
var xml11Declaration = regexp.MustCompile(`^\s*<\?xml\s+version\s*=\s*['"]1\.1['"]`)

func parse(content []byte) *node {
	if loc := xml11Declaration.FindIndex(content); loc != nil {
		content = append([]byte(`<?xml version="1.0"`), content[loc[1]:]...)
	}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	decoder.Strict = false
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	root := &node{}
	current := root
	for depth := 0; ; {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch item := token.(type) {
		case xml.StartElement:
			if depth >= 64 {
				return root
			}
			child := &node{name: item.Name.Local, parent: current}
			current.children = append(current.children, child)
			current = child
			depth++
		case xml.EndElement:
			if current.parent != nil {
				current = current.parent
				depth--
			}
		case xml.CharData:
			if current.text.Len() < 64*1024 {
				current.text.Write(item)
			}
		}
	}
	if len(root.children) == 0 {
		return nil
	}
	return root
}

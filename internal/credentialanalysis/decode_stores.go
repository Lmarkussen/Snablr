package credentialanalysis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"strings"
)

// Remote-access clients that protect saved passwords only with a public
// key or a fixed obfuscation. A store protected with the user's own master
// password (WinSCP master password, FileZilla "crypt", mRemoteNG custom
// password) does not decode and stays review material.

const (
	decodedWinSCPBasis    = "WinSCP saved password decoded (fixed obfuscation)"
	decodedFileZillaBasis = "FileZilla saved password decoded (base64)"
	decodedMRemoteNGBasis = "mRemoteNG saved password decrypted with the default key"
)

// publicKeyDecoded reports whether a candidate's plaintext was recovered by
// decoding a value protected only by a public key or fixed obfuscation.
func publicKeyDecoded(basis string) bool {
	switch basis {
	case decodedWinSCPBasis, decodedFileZillaBasis, decodedMRemoteNGBasis, decodedVNCBasis, decodedTeamViewerBasis:
		return true
	default:
		return false
	}
}

const (
	winSCPMagic = 0xA3
	winSCPFlag  = 0xFF
)

// DecodeWinSCPPassword reverses the obfuscation WinSCP applies to a saved
// session password (the hex Password= value) without a master password. The
// current format embeds user+host as a prefix, which must match.
func DecodeWinSCPPassword(host, user, hexPassword string) (string, bool) {
	value := strings.TrimSpace(hexPassword)
	if value == "" || len(value)%2 != 0 {
		return "", false
	}
	data := make([]byte, 0, len(value)/2)
	for i := 0; i < len(value); i += 2 {
		b, err := strconv.ParseUint(value[i:i+2], 16, 8)
		if err != nil {
			return "", false
		}
		data = append(data, ^(byte(b) ^ winSCPMagic))
	}
	next := func() (byte, bool) {
		if len(data) == 0 {
			return 0, false
		}
		b := data[0]
		data = data[1:]
		return b, true
	}
	flag, ok := next()
	if !ok {
		return "", false
	}
	length := int(flag)
	if flag == winSCPFlag {
		if _, ok = next(); !ok {
			return "", false
		}
		l, ok := next()
		if !ok {
			return "", false
		}
		length = int(l)
	}
	shift, ok := next()
	if !ok || int(shift) > len(data) {
		return "", false
	}
	data = data[shift:]
	if length > len(data) {
		return "", false
	}
	text := string(data[:length])
	if flag == winSCPFlag {
		key := user + host
		if !strings.HasPrefix(text, key) {
			return "", false
		}
		text = strings.TrimPrefix(text, key)
	}
	return printableText(text)
}

// DecodeFileZillaPassword decodes a FileZilla <Pass encoding="base64">.
func DecodeFileZillaPassword(value string) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	return printableText(string(data))
}

// mRemoteNGDefaultPassword is the key mRemoteNG uses when the user has not
// set a master password.
const mRemoteNGDefaultPassword = "mR3m"

// DecodeMRemoteNGPassword decrypts a confCons.xml Password attribute with
// the default key. gcm selects the AES-GCM format (EncryptionEngine="AES",
// BlockCipherMode="GCM", mRemoteNG 1.76 and later); otherwise the older
// AES-CBC format is used. GCM authenticates the result, so a store with a
// custom master password fails cleanly.
func DecodeMRemoteNGPassword(value string, gcm bool, iterations int) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(data) == 0 {
		return "", false
	}
	if gcm {
		const saltSize, nonceSize, tagSize = 16, 16, 16
		if len(data) <= saltSize+nonceSize+tagSize {
			return "", false
		}
		if iterations <= 0 {
			iterations = 1000
		}
		salt, nonce, sealed := data[:saltSize], data[saltSize:saltSize+nonceSize], data[saltSize+nonceSize:]
		key, err := pbkdf2.Key(sha1.New, mRemoteNGDefaultPassword, salt, iterations, 32)
		if err != nil {
			return "", false
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", false
		}
		aead, err := cipher.NewGCMWithNonceSize(block, nonceSize)
		if err != nil {
			return "", false
		}
		plain, err := aead.Open(nil, nonce, sealed, salt)
		if err != nil {
			return "", false
		}
		return printableText(string(plain))
	}
	if len(data) <= aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return "", false
	}
	key := md5.Sum([]byte(mRemoteNGDefaultPassword))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", false
	}
	iv, sealed := data[:aes.BlockSize], data[aes.BlockSize:]
	plain := make([]byte, len(sealed))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, sealed)
	plain, ok := stripPKCS7(plain)
	if !ok {
		return "", false
	}
	return printableText(string(plain))
}

// harvestWinSCPSessions decodes saved passwords in a WinSCP.ini: each
// [Sessions\...] section holds HostName, UserName and Password.
func harvestWinSCPSessions(text string, add func(Candidate)) {
	var section map[string]string
	flush := func() {
		if section == nil || section["password"] == "" || section["username"] == "" {
			return
		}
		plaintext, ok := DecodeWinSCPPassword(section["hostname"], section["username"], section["password"])
		if !ok {
			return
		}
		add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: section["username"], Value: plaintext, ValidationBasis: decodedWinSCPBasis})
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = nil
			if strings.HasPrefix(strings.ToLower(line), `[sessions\`) {
				section = map[string]string{}
			}
			continue
		}
		if section == nil {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			section[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	flush()
}

// harvestFileZillaServer decodes a FileZilla <Server> or recent-server
// <Item> with <User> and <Pass encoding="base64">.
func harvestFileZillaServer(node *xmlHarvestNode, add func(Candidate)) {
	var pass *xmlHarvestNode
	for _, child := range node.children {
		if strings.EqualFold(child.name, "pass") {
			pass = child
		}
	}
	if pass == nil || !strings.EqualFold(pass.attrs["encoding"], "base64") {
		return
	}
	user, _ := xmlChildValue(node, "user")
	plaintext, ok := DecodeFileZillaPassword(pass.text)
	if !ok || strings.TrimSpace(user) == "" {
		return
	}
	add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: strings.TrimSpace(user), Value: plaintext, ValidationBasis: decodedFileZillaBasis})
}

// harvestMRemoteNGNode decrypts the Password attribute of a confCons.xml
// connection <Node> with the default key, using the format settings of the
// <Connections> root.
func harvestMRemoteNGNode(node *xmlHarvestNode, add func(Candidate)) {
	if !strings.EqualFold(node.name, "node") || strings.TrimSpace(node.attrs["password"]) == "" {
		return
	}
	root := node
	for root.parent != nil {
		root = root.parent
	}
	if !strings.EqualFold(root.name, "connections") || strings.EqualFold(root.attrs["full_file_encryption"], "true") {
		return
	}
	gcm := strings.EqualFold(root.attrs["encryption_engine"], "aes") && strings.EqualFold(firstNonEmpty(root.attrs["block_cipher_mode"], "gcm"), "gcm")
	iterations, _ := strconv.Atoi(root.attrs["kdf_iterations"])
	plaintext, ok := DecodeMRemoteNGPassword(node.attrs["password"], gcm, iterations)
	if !ok {
		return
	}
	identity := strings.TrimSpace(node.attrs["username"])
	if identity == "" {
		return
	}
	if domain := strings.TrimSpace(node.attrs["domain"]); domain != "" {
		identity = domain + `\` + identity
	}
	add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: identity, Value: plaintext, ValidationBasis: decodedMRemoteNGBasis})
}

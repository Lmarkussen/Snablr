// Package securityparse parses the supported, modern Windows SECURITY hive
// structures using a boot key derived from the paired SYSTEM hive. It returns
// metadata only; decrypted secret bytes never leave this package.
package securityparse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"snablr/internal/registryhive"
)

const (
	maxSecretRecords = 4096
	maxSecretBytes   = 16 << 20
	maxCacheRecords  = 64
)

var (
	ErrUnsupportedRevision = errors.New("unsupported SECURITY hive LSA revision")
	ErrMissingPolicyKey    = errors.New("SECURITY hive LSA policy key is missing")
	ErrInvalidEncrypted    = errors.New("invalid encrypted LSA record")
)

type Status uint8

const (
	StatusIncomplete Status = iota
	StatusParsed
	StatusMalformed
	StatusUnsupported
)

type SecretRecord struct {
	Name             string `json:"name"`
	Category         string `json:"category"`
	ValueKind        string `json:"value_kind"`
	Current          bool   `json:"current"`
	Decoded          bool   `json:"decoded"`
	SecretLength     int    `json:"secret_length"`
	RawSecretPresent bool   `json:"raw_secret_present"`
}

type CacheRecord struct {
	Slot            string `json:"slot"`
	Username        string `json:"username,omitempty"`
	Domain          string `json:"domain,omitempty"`
	Iteration       uint32 `json:"iteration,omitempty"`
	Decoded         bool   `json:"decoded"`
	MaterialPresent bool   `json:"material_present"`
	verifier        []byte
}

type Result struct {
	Status              Status
	Revision            string
	LSAKeyDerived       bool
	SecretsFound        int
	SecretsDecoded      int
	Secrets             []SecretRecord
	CachedDomainFound   int
	CachedDomainDecoded int
	CachedDomain        []CacheRecord
	Warnings            []string
}

// Parse decodes modern Vista+ SECURITY LSA records using the supplied SYSTEM
// boot key. Raw keys and plaintext values are deliberately not represented in
// Result.
func Parse(hive *registryhive.Reader, bootKey [16]byte) (Result, error) {
	if hive == nil {
		return Result{Status: StatusMalformed}, errors.New("SECURITY hive is nil")
	}
	policy, err := hive.OpenKey(`Policy`)
	if err != nil {
		return Result{Status: StatusMalformed}, fmt.Errorf("open SECURITY policy: %w", err)
	}
	polEKKey, err := policy.Child("PolEKList")
	if err != nil {
		return Result{Status: StatusUnsupported}, fmt.Errorf("%w: PolEKList", ErrMissingPolicyKey)
	}
	polEK, err := polEKKey.Value("")
	if err != nil {
		return Result{Status: StatusUnsupported}, fmt.Errorf("%w: PolEKList default value", ErrMissingPolicyKey)
	}
	lsaKey, err := unwrapModernKey(polEK.Raw, bootKey)
	if err != nil {
		return Result{Status: StatusMalformed, Revision: "modern"}, err
	}
	result := Result{Status: StatusParsed, Revision: "modern", LSAKeyDerived: true}
	var nlkmKey []byte
	secretsKey, err := policy.Child(`Secrets`)
	if err == nil {
		result.Secrets, result.SecretsDecoded, result.Warnings, nlkmKey = parseSecrets(secretsKey, lsaKey)
		result.SecretsFound = len(result.Secrets)
	}
	if cache, cacheErr := hive.OpenKey(`Cache`); cacheErr == nil {
		result.CachedDomain, result.CachedDomainFound, result.CachedDomainDecoded, result.Warnings = parseCache(cache, nlkmKey, result.Warnings)
	}
	return result, nil
}

func unwrapModernKey(data []byte, bootKey [16]byte) ([32]byte, error) {
	var out [32]byte
	plain, err := decryptModernRecord(data, bootKey[:])
	if err != nil {
		return out, fmt.Errorf("unwrap PolEKList: %w", err)
	}
	if len(plain) < 16 {
		return out, fmt.Errorf("%w: PolEKList plaintext", ErrInvalidEncrypted)
	}
	length := binary.LittleEndian.Uint32(plain[:4])
	if length == 0 || length > maxSecretBytes || int(length) > len(plain)-16 {
		return out, fmt.Errorf("%w: PolEKList plaintext length", ErrInvalidEncrypted)
	}
	secret := plain[16 : 16+length]
	if len(secret) >= 84 {
		secret = secret[52:]
	}
	if len(secret) < 32 {
		return out, fmt.Errorf("%w: LSA key length", ErrInvalidEncrypted)
	}
	copy(out[:], secret[:32])
	return out, nil
}

func decryptModernRecord(data []byte, key []byte) ([]byte, error) {
	if len(data) < 60 || len(data[60:]) == 0 || len(data[60:])%aes.BlockSize != 0 {
		return nil, ErrInvalidEncrypted
	}
	salt := data[28:60]
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	derived := h.Sum(nil)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(data[60:]))
	// Vista+ offline SECURITY records are encrypted one AES block at a
	// time with a zero IV. This is distinct from cached-domain records,
	// which use chained CBC with their record IV below.
	for offset := 0; offset < len(plain); offset += aes.BlockSize {
		block.Decrypt(plain[offset:offset+aes.BlockSize], data[60+offset:60+offset+aes.BlockSize])
	}
	return plain, nil
}

func parseSecrets(parent *registryhive.Key, lsaKey [32]byte) ([]SecretRecord, int, []string, []byte) {
	names, err := parent.Subkeys()
	if err != nil {
		return nil, 0, []string{fmt.Sprintf("enumerate LSA secrets: %v", err)}, nil
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	if len(names) > maxSecretRecords {
		names = names[:maxSecretRecords]
	}
	result := make([]SecretRecord, 0, len(names))
	decoded := 0
	warnings := []string{}
	var nlkmKey []byte
	for _, name := range names {
		secretKey, err := parent.Child(name)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open LSA secret %s: %v", name, err))
			continue
		}
		for _, version := range []struct {
			name    string
			current bool
		}{
			{name: "CurrVal", current: true}, {name: "OldVal", current: false},
		} {
			valueKey, err := secretKey.Child(version.name)
			if err != nil {
				continue
			}
			value, err := valueKey.Value("")
			if err != nil || len(value.Raw) == 0 {
				continue
			}
			decodedSecret, err := decryptModernRecord(value.Raw, lsaKey[:])
			record := SecretRecord{Name: name, Category: categorize(name), ValueKind: valueKind(name), Current: version.current, RawSecretPresent: true}
			if err == nil {
				length := uint32(0)
				if len(decodedSecret) >= 4 {
					length = binary.LittleEndian.Uint32(decodedSecret[:4])
				}
				if length > 0 && length <= maxSecretBytes && int(length) <= len(decodedSecret)-16 {
					record.Decoded = true
					record.SecretLength = int(length)
					if length >= 84 {
						record.SecretLength -= 52
					}
					decoded++
					if strings.EqualFold(name, "NL$KM") {
						secret := decodedSecret[16 : 16+length]
						if len(secret) >= 84 {
							secret = secret[52:84]
						}
						if key, keyErr := extractModernCacheKey(secret); keyErr == nil {
							nlkmKey = key
						}
					}
				}
			}
			result = append(result, record)
		}
	}
	return result, decoded, warnings, nlkmKey
}

func extractModernCacheKey(body []byte) ([]byte, error) {
	if len(body) < 32 {
		return nil, fmt.Errorf("modern NL$KM body is too short")
	}
	// The modern NL$KM secret's first 16-byte semantic field is the AES key
	// used for cached-domain records. The following field is separate key
	// material and is not the cache-record key.
	return append([]byte(nil), body[:aes.BlockSize]...), nil
}

func parseCache(cache *registryhive.Key, nlkmKey []byte, warnings []string) ([]CacheRecord, int, int, []string) {
	values, err := cache.Values()
	if err != nil {
		return nil, 0, 0, append(warnings, fmt.Sprintf("enumerate cached-domain records: %v", err))
	}
	iteration, iterationWarning := cacheIteration(values)
	if iterationWarning != "" {
		warnings = append(warnings, iterationWarning)
	}
	result := make([]CacheRecord, 0, len(values))
	decoded := 0
	for _, value := range values {
		if !strings.HasPrefix(strings.ToUpper(value.Name), "NL$") || strings.EqualFold(value.Name, "NL$Control") || strings.EqualFold(value.Name, "NL$IterationCount") {
			continue
		}
		if len(result) >= maxCacheRecords {
			break
		}
		record := CacheRecord{Slot: value.Name, MaterialPresent: len(value.Raw) > 0, Iteration: iteration}
		if len(nlkmKey) == aes.BlockSize && len(value.Raw) >= 96 {
			if username, domain, verifier, ok := decodeCacheRecord(value.Raw, nlkmKey); ok {
				record.Username, record.Domain, record.Decoded = username, domain, true
				record.verifier = verifier
				decoded++
			}
		}
		result = append(result, record)
	}
	return result, len(result), decoded, warnings
}

func cacheIteration(values []registryhive.Value) (uint32, string) {
	const defaultIteration = 10240
	for _, value := range values {
		if !strings.EqualFold(value.Name, "NL$IterationCount") {
			continue
		}
		if len(value.Raw) != 4 {
			return defaultIteration, "invalid NL$IterationCount value length"
		}
		raw := binary.LittleEndian.Uint32(value.Raw)
		if raw <= defaultIteration {
			return raw * 1024, ""
		}
		effective := raw &^ 1023
		if effective == 0 || effective > 1<<30 {
			return defaultIteration, "NL$IterationCount exceeds supported bounds"
		}
		return effective, ""
	}
	return defaultIteration, ""
}

func decodeCacheRecord(data, nlkmKey []byte) (string, string, []byte, bool) {
	if len(data) < 96 || len(nlkmKey) != aes.BlockSize {
		return "", "", nil, false
	}
	userLength := int(binary.LittleEndian.Uint16(data[0:2]))
	domainLength := int(binary.LittleEndian.Uint16(data[2:4]))
	dnsLength := int(binary.LittleEndian.Uint16(data[60:62]))
	flags := binary.LittleEndian.Uint32(data[48:52])
	if userLength < 0 || domainLength < 0 || dnsLength < 0 || userLength > maxSecretBytes || domainLength > maxSecretBytes || dnsLength > maxSecretBytes || flags&1 == 0 {
		return "", "", nil, false
	}
	iv := data[64:80]
	ciphertext := data[96:]
	if len(ciphertext) == 0 || len(ciphertext) > maxSecretBytes {
		return "", "", nil, false
	}
	block, err := aes.NewCipher(nlkmKey)
	if err != nil {
		return "", "", nil, false
	}
	// Native modern cache records may end with a partial encrypted chunk.
	// Windows-compatible readers decrypt that final chunk after zero-padding
	// it to one AES block; bound the rounded size before allocating.
	decryptedLength := (len(ciphertext) + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
	if decryptedLength < len(ciphertext) || decryptedLength > maxSecretBytes+aes.BlockSize {
		return "", "", nil, false
	}
	decrypted := make([]byte, decryptedLength)
	copy(decrypted, ciphertext)
	plain := make([]byte, decryptedLength)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, decrypted)
	if len(plain) < 0x48+userLength+domainLength || len(plain) < 16 {
		return "", "", nil, false
	}
	start := 0x48
	userBytes := plain[start : start+userLength]
	start += pad4(userLength)
	if start+domainLength > len(plain) || start+pad4(domainLength)+dnsLength > len(plain) {
		return "", "", nil, false
	}
	domainBytes := plain[start : start+domainLength]
	dnsBytes := plain[start+pad4(domainLength) : start+pad4(domainLength)+dnsLength]
	username, okUser := decodeUTF16String(userBytes)
	domain, okDomain := decodeUTF16String(domainBytes)
	if dnsLength > 0 {
		if decodedDNS, ok := decodeUTF16String(dnsBytes); ok {
			domain = decodedDNS
		} else {
			return "", "", nil, false
		}
	}
	if !okUser || !okDomain {
		return "", "", nil, false
	}
	if !cacheIdentity(username) || !cacheIdentity(domain) {
		return "", "", nil, false
	}
	return username, domain, append([]byte(nil), plain[:16]...), true
}

func pad4(value int) int { return (value + 3) &^ 3 }

func decodeUTF16String(data []byte) (string, bool) {
	if len(data)%2 != 0 {
		return "", false
	}
	values := make([]uint16, len(data)/2)
	for i := range values {
		values[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	decoded := utf16.Decode(values)
	for _, value := range decoded {
		if value == 0 || value < 0x20 || value == 0xfffd {
			return "", false
		}
	}
	return string(decoded), true
}

func cacheIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strings.ContainsRune("._-\\/@", ch) {
			continue
		}
		return false
	}
	return true
}

func categorize(name string) string {
	upper := strings.ToUpper(name)
	switch {
	case upper == "$MACHINE.ACC":
		return "machine-account"
	case upper == "DPAPI_SYSTEM":
		return "dpapi-system"
	case upper == "NL$KM":
		return "cached-domain-key"
	case strings.HasPrefix(upper, "_SC_"):
		return "service-account"
	case strings.HasPrefix(upper, "DEFAULTPASSWORD"):
		return "default-password"
	default:
		return "unknown"
	}
}

func valueKind(name string) string {
	upper := strings.ToUpper(name)
	if upper == "$MACHINE.ACC" || strings.HasPrefix(upper, "_SC_") || strings.HasPrefix(upper, "DEFAULTPASSWORD") {
		return "credential-like"
	}
	return "opaque-secret"
}

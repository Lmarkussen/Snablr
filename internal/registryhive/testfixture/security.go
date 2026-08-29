package testfixture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"unicode/utf16"
)

// SecuritySpec controls a deterministic modern SECURITY hive fixture. Values
// are synthetic test data and are never exported by the parser.
type SecuritySpec struct {
	BootKey            [16]byte
	LSAKey             [32]byte
	Secrets            map[string][]byte
	CacheEntries       []CacheEntry
	CacheSlots         int
	IterationCount     *uint32
	MalformedIteration bool
	CorruptPolicy      bool
	CorruptCache       bool
	WrongCacheKey      bool
	UnalignedCache     bool
}

type CacheEntry struct {
	Username string
	Domain   string
	Verifier [16]byte
}

// BuildSecurity creates a valid REGF-shaped modern SECURITY hive.
func BuildSecurity(spec SecuritySpec) []byte {
	b := &builder{b: make([]byte, base+bins), next: 0x20}
	copy(b.b[:4], "regf")
	binary.LittleEndian.PutUint32(b.b[20:], 1)
	binary.LittleEndian.PutUint32(b.b[24:], 5)
	copy(b.b[base:base+4], "hbin")
	binary.LittleEndian.PutUint32(b.b[base+8:], bins)
	root := b.nk("SECURITY")
	binary.LittleEndian.PutUint16(b.payload(root)[2:], 0x2c)
	policy := b.nk("Policy")
	policyData := encryptModernFixture(spec.BootKey[:], lsaSecretBlob(spec.LSAKey[:]), 1)
	if spec.CorruptPolicy {
		policyData = []byte("bad")
	}
	polKey := b.nk("PolEKList")
	pol := b.vk("", 3, policyData)
	b.setValues(polKey, 1, b.valueList(pol))
	secrets := b.nk("Secrets")
	secretNames := make([]string, 0, len(spec.Secrets))
	for name := range spec.Secrets {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	secretChildren := make([]uint32, 0, len(secretNames))
	for index, name := range secretNames {
		secret := b.nk(name)
		curr := b.nk("CurrVal")
		secretValue := lsaSecretBlob(spec.Secrets[name])
		// NL$KM is consumed by the modern cache format from the first
		// semantic 16-byte field, unlike ordinary LSA blobs.
		if name == "NL$KM" {
			secretValue = append([]byte(nil), spec.Secrets[name]...)
		}
		value := b.vk("", 3, encryptModernFixture(spec.LSAKey[:], secretValue, byte(index+2)))
		b.setValues(curr, 1, b.valueList(value))
		b.setChildren(secret, []uint32{curr})
		secretChildren = append(secretChildren, secret)
	}
	b.setChildren(secrets, secretChildren)
	cache := b.nk("Cache")
	cacheValues := make([]uint32, 0, spec.CacheSlots+len(spec.CacheEntries)+1)
	nlkmMaterial := spec.LSAKey
	if material, ok := spec.Secrets["NL$KM"]; ok && len(material) >= 32 {
		copy(nlkmMaterial[:], material[:32])
	}
	for i, entry := range spec.CacheEntries {
		name := "NL$" + string(rune('1'+i))
		cacheData := buildCacheFixture(entry, nlkmMaterial, i, spec.UnalignedCache)
		if spec.WrongCacheKey {
			wrongKey := [32]byte{}
			for j := range wrongKey {
				wrongKey[j] = 0x99
			}
			cacheData = buildCacheFixture(entry, wrongKey, i, spec.UnalignedCache)
		}
		if spec.CorruptCache {
			cacheData = cacheData[:32]
		}
		if spec.UnalignedCache && len(cacheData) > 104 {
			cacheData = cacheData[:len(cacheData)-8]
		}
		cacheValues = append(cacheValues, b.vk(name, 3, cacheData))
	}
	for i := len(spec.CacheEntries) + 1; i <= spec.CacheSlots; i++ {
		name := "NL$" + string(rune('0'+i))
		cacheValues = append(cacheValues, b.vk(name, 3, nil))
	}
	if spec.IterationCount != nil {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, *spec.IterationCount)
		if spec.MalformedIteration {
			raw = raw[:2]
		}
		cacheValues = append(cacheValues, b.vk("NL$IterationCount", 4, raw))
	} else if spec.MalformedIteration {
		cacheValues = append(cacheValues, b.vk("NL$IterationCount", 4, []byte{1, 2}))
	}
	b.setValues(cache, uint32(len(cacheValues)), b.valueList(cacheValues...))
	b.setChildren(policy, []uint32{polKey, secrets})
	b.setChildren(root, []uint32{policy, cache})
	binary.LittleEndian.PutUint32(b.b[36:], root)
	binary.LittleEndian.PutUint32(b.b[40:], bins)
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(b.b[i:])
	}
	binary.LittleEndian.PutUint32(b.b[508:], checksum)
	return b.b
}

func lsaSecretBlob(value []byte) []byte {
	blob := make([]byte, 52+len(value))
	binary.LittleEndian.PutUint32(blob, uint32(len(blob)))
	copy(blob[52:], value)
	return blob
}

func buildCacheFixture(entry CacheEntry, key [32]byte, index int, unaligned bool) []byte {
	user := utf16Bytes(entry.Username)
	domain := utf16Bytes(entry.Domain)
	plain := make([]byte, 0x48+padFixture(len(user))+len(domain)+padFixture(len(domain)))
	copy(plain[:16], entry.Verifier[:])
	copy(plain[0x48:], user)
	copy(plain[0x48+padFixture(len(user)):], domain)
	copy(plain[0x48+padFixture(len(user))+padFixture(len(domain)):], domain)
	if unaligned {
		plain = append(plain, make([]byte, aes.BlockSize)...)
	}
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}
	data := make([]byte, 96+len(plain))
	binary.LittleEndian.PutUint16(data[0:], uint16(len(user)))
	binary.LittleEndian.PutUint16(data[2:], uint16(len(domain)))
	binary.LittleEndian.PutUint16(data[60:], uint16(len(domain)))
	binary.LittleEndian.PutUint32(data[48:], 1)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(index + i + 1)
	}
	copy(data[64:80], iv)
	block, _ := aes.NewCipher(key[:16])
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data[96:], plain)
	return data
}

func padFixture(value int) int { return (value + 3) &^ 3 }

func utf16Bytes(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	out := make([]byte, len(encoded)*2)
	for i, u := range encoded {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func encryptModernFixture(key, secret []byte, saltByte byte) []byte {
	inner := make([]byte, 16+len(secret))
	binary.LittleEndian.PutUint32(inner, uint32(len(secret)))
	copy(inner[16:], secret)
	for len(inner)%aes.BlockSize != 0 {
		inner = append(inner, 0)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = saltByte + byte(i)
	}
	h := sha256.New()
	h.Write(key)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	derived := h.Sum(nil)
	block, _ := aes.NewCipher(derived)
	ciphertext := make([]byte, len(inner))
	for offset := 0; offset < len(inner); offset += aes.BlockSize {
		block.Encrypt(ciphertext[offset:offset+aes.BlockSize], inner[offset:offset+aes.BlockSize])
	}
	record := make([]byte, 60+len(ciphertext))
	binary.LittleEndian.PutUint32(record, 1)
	copy(record[28:], salt)
	copy(record[60:], ciphertext)
	return record
}

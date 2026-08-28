// Package samparse reads offline Windows SAM hives and recovers local account
// hash material when the supplied SYSTEM boot key and SAM records are valid.
// It has no scanner, WIM, SMB, or reporting dependencies.
package samparse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"snablr/internal/registryhive"
)

var (
	ErrInvalidInput        = errors.New("invalid SAM parser input")
	ErrMissingDomain       = errors.New("SAM domain account key is missing")
	ErrMissingDomainValue  = errors.New("SAM domain account value is missing")
	ErrUnsupportedRevision = errors.New("unsupported SAM revision")
	ErrMalformedRecord     = errors.New("malformed SAM record")
	ErrInvalidChecksum     = errors.New("invalid SAM key checksum")
	ErrUnsupportedHash     = errors.New("unsupported SAM hash revision")
)

const (
	HashAbsent HashStatus = iota
	HashRecovered
	HashUnsupported
	HashMalformed
)

// HashStatus describes whether a hash was present and safely processed.
type HashStatus uint8

// HashResult contains a recovered fixed-size hash only when Status is HashRecovered.
type HashResult struct {
	Status HashStatus
	Value  [16]byte
}

// Account is a structured local SAM account. Hash values are never serialized by this package.
type Account struct {
	Username string
	RID      uint32
	Enabled  *bool
	NT       HashResult
	LM       HashResult
}

// AccountError records an account-local failure while allowing other accounts to be returned.
type AccountError struct {
	RID uint32
	Err error
}

// Result contains successfully parsed accounts and non-fatal account diagnostics.
type Result struct {
	Accounts    []Account
	Errors      []AccountError
	SAMRevision uint32
}

// Inputs supplies an already-open SAM hive and the boot key derived from SYSTEM.
type Inputs struct {
	SAM     *registryhive.Reader
	BootKey [16]byte
}

// Parse parses the SAM domain key and local user records. Domain-key failures are fatal;
// malformed individual users are recorded in Result.Errors and do not discard other users.
func Parse(inputs Inputs) (Result, error) {
	if inputs.SAM == nil {
		return Result{}, fmt.Errorf("%w: nil SAM hive", ErrInvalidInput)
	}
	accountKey, err := openFirst(inputs.SAM, `Domains\Account`, `SAM\Domains\Account`)
	if err != nil {
		return Result{}, fmt.Errorf("%w", ErrMissingDomain)
	}
	fValue, err := accountKey.Value("F")
	if err != nil {
		return Result{}, fmt.Errorf("%w: Account\\F", ErrMissingDomainValue)
	}
	samKey, revision, err := deriveSAMKey(fValue.Bytes(), inputs.BootKey)
	if err != nil {
		return Result{}, err
	}
	users, err := openFirst(inputs.SAM, `Domains\Account\Users`, `SAM\Domains\Account\Users`)
	if err != nil {
		return Result{}, fmt.Errorf("%w: Users", ErrMissingDomain)
	}
	names, err := users.Subkeys()
	if err != nil {
		return Result{}, err
	}
	type ridName struct {
		rid  uint32
		name string
	}
	rids := []ridName{}
	seen := map[uint32]bool{}
	result := Result{SAMRevision: revision}
	for _, name := range names {
		if strings.EqualFold(name, "Names") {
			continue
		}
		rid, ok := parseRID(name)
		if !ok {
			result.Errors = append(result.Errors, AccountError{Err: fmt.Errorf("%w: invalid user RID name", ErrMalformedRecord)})
			continue
		}
		if !seen[rid] {
			seen[rid] = true
			rids = append(rids, ridName{rid, name})
		}
	}
	sort.Slice(rids, func(i, j int) bool { return rids[i].rid < rids[j].rid })
	result.Accounts = make([]Account, 0, len(rids))
	for _, item := range rids {
		account, accountErr := parseAccount(inputs.SAM, item.name, item.rid, samKey)
		if accountErr != nil {
			result.Errors = append(result.Errors, AccountError{RID: item.rid, Err: accountErr})
			continue
		}
		result.Accounts = append(result.Accounts, account)
	}
	clearBytes(samKey[:])
	return result, nil
}

func openFirst(hive *registryhive.Reader, paths ...string) (*registryhive.Key, error) {
	for _, path := range paths {
		if k, err := hive.OpenKey(path); err == nil {
			return k, nil
		}
	}
	return nil, registryhive.ErrKeyNotFound
}
func parseRID(name string) (uint32, bool) {
	if name == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(name, 16, 32)
	return uint32(v), err == nil
}

func deriveSAMKey(f []byte, boot [16]byte) ([16]byte, uint32, error) {
	var out [16]byte
	if len(f) < 0x68 {
		return out, 0, fmt.Errorf("%w: Account\\F header", ErrMalformedRecord)
	}
	revision := binary.LittleEndian.Uint32(f[0:4])
	if revision != 2 && revision != 3 {
		return out, revision, fmt.Errorf("%w: domain F revision", ErrUnsupportedRevision)
	}
	keyOffset := 0x70
	if len(f) < keyOffset+8 {
		return out, revision, fmt.Errorf("%w: Account\\F SAM key", ErrMalformedRecord)
	}
	keyRevision := binary.LittleEndian.Uint32(f[keyOffset:])
	keyData := f[keyOffset:]
	switch keyRevision {
	case 1:
		if len(keyData) < 0x40 {
			return out, revision, fmt.Errorf("%w: legacy SAM key length", ErrMalformedRecord)
		}
		length := binary.LittleEndian.Uint32(keyData[4:8])
		if length != 0 && (length < 0x20 || uint64(length) > uint64(len(keyData))) {
			return out, revision, fmt.Errorf("%w: legacy SAM key length", ErrMalformedRecord)
		}
		qwerty := []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
		digits := []byte("0123456789012345678901234567890123456789\x00")
		h := md5.New()
		h.Write(keyData[8:24])
		h.Write(qwerty)
		h.Write(boot[:])
		h.Write(digits)
		stream, _ := rc4.NewCipher(h.Sum(nil))
		encrypted := append([]byte(nil), keyData[24:56]...)
		stream.XORKeyStream(encrypted, encrypted)
		checkInput := make([]byte, 0, 16+len(digits)+16+len(qwerty))
		checkInput = append(checkInput, encrypted[:16]...)
		checkInput = append(checkInput, digits...)
		checkInput = append(checkInput, encrypted[:16]...)
		checkInput = append(checkInput, qwerty...)
		check := md5.Sum(checkInput)
		clearBytes(checkInput)
		if !equalBytes(check[:], encrypted[16:32]) {
			clearBytes(encrypted)
			return out, revision, fmt.Errorf("%w: legacy SAM key", ErrInvalidChecksum)
		}
		copy(out[:], encrypted[:16])
		clearBytes(encrypted)
		return out, revision, nil
	case 2:
		if len(keyData) < 0x20 {
			return out, revision, fmt.Errorf("%w: AES SAM key header", ErrMalformedRecord)
		}
		dataLen, checksumLen := binary.LittleEndian.Uint32(keyData[12:16]), binary.LittleEndian.Uint32(keyData[8:12])
		if dataLen == 0 || dataLen%aes.BlockSize != 0 || checksumLen == 0 || checksumLen%aes.BlockSize != 0 {
			return out, revision, fmt.Errorf("%w: AES SAM key lengths", ErrMalformedRecord)
		}
		endData, ok := checkedRange(0x20, uint64(dataLen), uint64(len(keyData)))
		if !ok {
			return out, revision, fmt.Errorf("%w: AES SAM key data", ErrMalformedRecord)
		}
		endCheck, ok := checkedRange(uint64(endData), uint64(checksumLen), uint64(len(keyData)))
		if !ok {
			return out, revision, fmt.Errorf("%w: AES SAM key checksum", ErrMalformedRecord)
		}
		block, err := aes.NewCipher(boot[:])
		if err != nil {
			return out, revision, fmt.Errorf("%w: AES SAM key cipher", ErrMalformedRecord)
		}
		plainData := make([]byte, dataLen)
		plainCheck := make([]byte, checksumLen)
		cipher.NewCBCDecrypter(block, keyData[16:32]).CryptBlocks(plainData, keyData[0x20:endData])
		cipher.NewCBCDecrypter(block, keyData[16:32]).CryptBlocks(plainCheck, keyData[endData:endCheck])
		if len(plainData) < 16 || len(plainCheck) < 32 || !equalBytes(sha256Bytes(plainData[:16]), plainCheck[:32]) {
			clearBytes(plainData)
			clearBytes(plainCheck)
			return out, revision, fmt.Errorf("%w: AES SAM key", ErrInvalidChecksum)
		}
		copy(out[:], plainData[:16])
		clearBytes(plainData)
		clearBytes(plainCheck)
		return out, revision, nil
	default:
		return out, revision, fmt.Errorf("%w: domain key revision", ErrUnsupportedRevision)
	}
}

func parseAccount(hive *registryhive.Reader, name string, rid uint32, samKey [16]byte) (Account, error) {
	key, err := hive.OpenKey(`SAM\Domains\Account\Users\` + name)
	if err != nil {
		key, err = hive.OpenKey(`Domains\Account\Users\` + name)
	}
	if err != nil {
		return Account{}, fmt.Errorf("%w: user key", ErrMalformedRecord)
	}
	v, err := key.Value("V")
	if err != nil {
		return Account{}, fmt.Errorf("%w: user V", ErrMalformedRecord)
	}
	data := v.Bytes()
	if len(data) < 0xcc {
		return Account{}, fmt.Errorf("%w: user V header", ErrMalformedRecord)
	}
	nameBytes, err := vField(data, 0x0c, 0xcc, true)
	if err != nil {
		return Account{}, err
	}
	username, err := decodeUTF16(nameBytes)
	if err != nil || username == "" {
		return Account{}, fmt.Errorf("%w: username", ErrMalformedRecord)
	}
	a := Account{Username: username, RID: rid, NT: HashResult{Status: HashAbsent}, LM: HashResult{Status: HashAbsent}}
	if fv, e := key.Value("F"); e == nil {
		raw := fv.Bytes()
		if len(raw) >= 0x3a {
			enabled := binary.LittleEndian.Uint16(raw[0x38:0x3a])&1 == 0
			a.Enabled = &enabled
		}
	}
	for _, field := range []struct {
		off      uint32
		target   *HashResult
		constant []byte
	}{{0x9c, &a.LM, []byte("LMPASSWORD\x00")}, {0xa8, &a.NT, []byte("NTPASSWORD\x00")}} {
		blob, e := vField(data, field.off, 0xcc, false)
		if e != nil {
			return Account{}, e
		}
		if len(blob) == 0 {
			continue
		}
		status, hash := decryptHash(blob, rid, samKey, field.constant)
		*field.target = HashResult{Status: status, Value: hash}
	}
	return a, nil
}

func vField(data []byte, headerOffset, base uint32, utf bool) ([]byte, error) {
	if uint64(headerOffset)+8 > uint64(base) {
		return nil, fmt.Errorf("%w: V field header", ErrMalformedRecord)
	}
	off := binary.LittleEndian.Uint32(data[headerOffset:])
	length := binary.LittleEndian.Uint32(data[headerOffset+4:])
	start, ok := checkedRange(uint64(base), uint64(off), uint64(len(data)))
	if !ok {
		return nil, fmt.Errorf("%w: V field offset", ErrMalformedRecord)
	}
	end, ok := checkedRange(uint64(start), uint64(length), uint64(len(data)))
	if !ok {
		return nil, fmt.Errorf("%w: V field length", ErrMalformedRecord)
	}
	out := data[start:end]
	if utf && len(out)%2 != 0 {
		return nil, fmt.Errorf("%w: username encoding", ErrMalformedRecord)
	}
	return out, nil
}

func decryptHash(blob []byte, rid uint32, samKey [16]byte, constant []byte) (HashStatus, [16]byte) {
	var out [16]byte
	if len(blob) < 4 {
		return HashMalformed, out
	}
	revision := binary.LittleEndian.Uint16(blob[2:4])
	var obfuscated []byte
	switch revision {
	case 1:
		if len(blob) != 20 {
			return HashMalformed, out
		}
		h := md5.New()
		h.Write(samKey[:])
		var ridBytes [4]byte
		binary.LittleEndian.PutUint32(ridBytes[:], rid)
		h.Write(ridBytes[:])
		h.Write(constant)
		c, _ := rc4.NewCipher(h.Sum(nil))
		obfuscated = make([]byte, 16)
		c.XORKeyStream(obfuscated, blob[4:])
	case 2:
		if len(blob) < 40 || (len(blob)-24)%aes.BlockSize != 0 || binary.LittleEndian.Uint32(blob[4:8]) == 0 {
			return HashMalformed, out
		}
		block, err := aes.NewCipher(samKey[:])
		if err != nil {
			return HashMalformed, out
		}
		plain := make([]byte, len(blob)-24)
		cipher.NewCBCDecrypter(block, blob[8:24]).CryptBlocks(plain, blob[24:])
		obfuscated = append([]byte(nil), plain[:16]...)
		clearBytes(plain)
	default:
		return HashUnsupported, out
	}
	keys, ok := ridDESKeys(rid)
	if !ok {
		clearBytes(obfuscated)
		return HashMalformed, out
	}
	b1, err1 := des.NewCipher(keys[0][:])
	b2, err2 := des.NewCipher(keys[1][:])
	if err1 != nil || err2 != nil {
		clearBytes(obfuscated)
		return HashMalformed, out
	}
	b1.Decrypt(out[0:8], obfuscated[0:8])
	b2.Decrypt(out[8:16], obfuscated[8:16])
	clearBytes(obfuscated)
	return HashRecovered, out
}

// ridDESKeys returns the two parity-adjusted DES keys required by SAM hash records.
func ridDESKeys(rid uint32) ([2][8]byte, bool) {
	var out [2][8]byte
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], rid)
	out[0] = expandDES([7]byte{b[0], b[1], b[2], b[3], b[0], b[1], b[2]})
	out[1] = expandDES([7]byte{b[3], b[0], b[1], b[2], b[3], b[0], b[1]})
	return out, true
}
func expandDES(in [7]byte) [8]byte {
	var out [8]byte
	out[0] = in[0] >> 1
	out[1] = ((in[0]&1)<<6 | in[1]>>2)
	out[2] = ((in[1]&3)<<5 | in[2]>>3)
	out[3] = ((in[2]&7)<<4 | in[3]>>4)
	out[4] = ((in[3]&15)<<3 | in[4]>>5)
	out[5] = ((in[4]&31)<<2 | in[5]>>6)
	out[6] = ((in[5]&63)<<1 | in[6]>>7)
	out[7] = in[6] & 0x7f
	for i := range out {
		out[i] <<= 1
		out[i] |= 1 ^ (byteOnes(out[i]) & 1)
	}
	return out
}
func byteOnes(v byte) byte {
	n := byte(0)
	for v != 0 {
		n += v & 1
		v >>= 1
	}
	return n
}
func checkedRange(start, length, limit uint64) (int, bool) {
	if start > limit || length > limit-start || start+length > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(start + length), true
}
func decodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", ErrMalformedRecord
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", ErrMalformedRecord
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", ErrMalformedRecord
		}
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00"), nil
}
func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

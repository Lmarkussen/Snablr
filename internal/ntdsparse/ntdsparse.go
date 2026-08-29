// Package ntdsparse reads the current NT credential attributes from an
// offline NTDS.DIT paired with its SYSTEM hive boot key. It exposes account
// metadata only; recovered hashes remain in an unexported field.
package ntdsparse

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Velocidex/ordereddict"
	ese "www.velocidex.com/golang/go-ese/parser"
)

const (
	maxRows       = 2_000_000
	maxBlobBytes  = 16 << 20
	maxPEKEntries = 256
	maxAccounts   = 1_000_000
	maxDatabase   = int64(16 << 30)
)

var (
	ErrInvalidInput        = errors.New("invalid NTDS parser input")
	ErrMissingPEK          = errors.New("NTDS PEK list is missing")
	ErrUnsupportedRevision = errors.New("unsupported NTDS encryption revision")
	ErrMalformedRecord     = errors.New("malformed NTDS record")
)

// Account is safe account metadata. NTHash is deliberately unexported and is
// never included in JSON, text formatting, or ordinary report structures.
type Account struct {
	SamAccountName       string `json:"sam_account_name"`
	Domain               string `json:"domain,omitempty"`
	RID                  uint32 `json:"rid"`
	SID                  string `json:"sid,omitempty"`
	Machine              bool   `json:"machine"`
	Disabled             bool   `json:"disabled"`
	CurrentNTHashPresent bool   `json:"current_nt_hash_present"`
	ntHash               [16]byte
}

// CurrentNTHashForExport returns a copy only for explicit highly-sensitive
// credential export. The hash is absent from JSON and ordinary reports.
func (a Account) CurrentNTHashForExport() []byte {
	if !a.CurrentNTHashPresent {
		return nil
	}
	hash := make([]byte, len(a.ntHash))
	copy(hash, a.ntHash[:])
	return hash
}

// Result contains bounded, safe NTDS metadata.
type Result struct {
	DatabaseVersion       uint32
	RowsConsidered        int
	AccountsDiscovered    int
	UserAccounts          int
	MachineAccounts       int
	DisabledAccounts      int
	AccountsWithCurrentNT int
	Accounts              []Account
	PEKRevision           uint32
}

type Input struct {
	Reader  io.ReaderAt
	Size    int64
	BootKey [16]byte
	Context context.Context
}

// Parse opens the ESE catalog and streams the directory table twice: once to
// locate the PEK list and once to decode account rows. No database mutation is
// performed and no whole-database buffer is allocated.
func Parse(in Input) (result Result, err error) {
	if in.Reader == nil || in.Size <= 0 || in.Size > maxDatabase {
		return result, ErrInvalidInput
	}
	ctx := in.Context
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("NTDS parser rejected database: %v", recovered)
		}
	}()

	eseCtx, err := ese.NewESEContext(in.Reader)
	if err != nil {
		return result, fmt.Errorf("open NTDS ESE database: %w", err)
	}
	result.DatabaseVersion = eseCtx.Version
	catalog, err := ese.ReadCatalog(eseCtx)
	if err != nil {
		return result, fmt.Errorf("read NTDS ESE catalog: %w", err)
	}
	if _, ok := catalog.Tables.Get("datatable"); !ok {
		return result, errors.New("NTDS datatable is missing")
	}

	var pekData []byte
	rows := 0
	err = catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows++
		if rows > maxRows {
			return fmt.Errorf("NTDS row limit exceeded")
		}
		if value, ok := binaryColumn(row, "ATTk590689"); ok && len(value) > 0 && len(value) <= maxBlobBytes {
			pekData = append([]byte(nil), value...)
			return errStopRows
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopRows) {
		return result, fmt.Errorf("read NTDS PEK row: %w", err)
	}
	if len(pekData) == 0 {
		return result, ErrMissingPEK
	}
	defer clearBytes(pekData)
	peks, revision, err := decryptPEKs(pekData, in.BootKey)
	if err != nil {
		return result, err
	}
	defer clearPEKs(peks)
	result.PEKRevision = revision

	rows = 0
	seen := make(map[string]struct{})
	err = catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows++
		if rows > maxRows {
			return fmt.Errorf("NTDS row limit exceeded")
		}
		result.RowsConsidered++
		name, ok := row.GetString("ATTm590045")
		if !ok || strings.TrimSpace(name) == "" {
			return nil
		}
		sid, ok := binaryColumn(row, "ATTr589970")
		if !ok || len(sid) < 8 {
			return nil
		}
		// Offline NTDS datatable SID sub-authorities use the canonical
		// big-endian representation expected by the native offline readers.
		rid := binary.BigEndian.Uint32(sid[len(sid)-4:])
		identity := strings.ToLower(name) + fmt.Sprintf("\x00%d", rid)
		if _, exists := seen[identity]; exists {
			return nil
		}
		if !isAccountObject(row) {
			return nil
		}
		seen[identity] = struct{}{}
		account := Account{SamAccountName: name, Domain: accountDomain(row), RID: rid, SID: sidString(sid), Machine: strings.HasSuffix(name, "$"), Disabled: userAccountControlDisabled(row)}
		if encrypted, ok := binaryColumn(row, "ATTk589914"); ok && len(encrypted) > 0 && len(encrypted) <= maxBlobBytes {
			if pek, ok := peks[encryptedPEKIndex(encrypted)]; ok {
				if hash, decryptErr := decryptCurrentHash(encrypted, pek, rid); decryptErr == nil {
					copy(account.ntHash[:], hash)
					account.CurrentNTHashPresent = true
					result.AccountsWithCurrentNT++
				}
			}
		}
		if len(result.Accounts) >= maxAccounts {
			return fmt.Errorf("NTDS account retention limit exceeded")
		}
		result.Accounts = append(result.Accounts, account)
		result.AccountsDiscovered++
		if account.Machine {
			result.MachineAccounts++
		} else {
			result.UserAccounts++
		}
		if account.Disabled {
			result.DisabledAccounts++
		}
		return nil
	})
	if err != nil {
		return result, fmt.Errorf("read NTDS account rows: %w", err)
	}
	return result, nil
}

func accountDomain(row *ordereddict.Dict) string {
	upn, ok := row.GetString("ATTm590480")
	if !ok {
		return ""
	}
	upn = strings.TrimSpace(upn)
	if at := strings.LastIndexByte(upn, '@'); at > 0 && at+1 < len(upn) {
		return upn[at+1:]
	}
	return ""
}

var errStopRows = errors.New("stop NTDS rows")

func binaryColumn(row *ordereddict.Dict, name string) ([]byte, bool) {
	value, ok := row.Get(name)
	if !ok || value == nil {
		return nil, false
	}
	switch typed := value.(type) {
	case []byte:
		if len(typed) > maxBlobBytes {
			return nil, false
		}
		return typed, true
	case string:
		if len(typed) > maxBlobBytes*2 || len(typed)%2 != 0 {
			return nil, false
		}
		decoded, err := hex.DecodeString(typed)
		return decoded, err == nil && len(decoded) <= maxBlobBytes
	default:
		return nil, false
	}
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func decryptPEK(data []byte, bootKey [16]byte) ([]byte, uint32, error) {
	peks, revision, err := decryptPEKs(data, bootKey)
	if err != nil {
		return nil, revision, err
	}
	pek, ok := peks[0]
	if !ok {
		return nil, revision, fmt.Errorf("%w: PEK index 0 missing", ErrMalformedRecord)
	}
	return pek, revision, nil
}

func decryptPEKs(data []byte, bootKey [16]byte) (map[uint32][]byte, uint32, error) {
	if len(data) < 24 {
		return nil, 0, fmt.Errorf("%w: PEK header", ErrMalformedRecord)
	}
	version := binary.LittleEndian.Uint32(data[:4])
	salt := data[8:24]
	var plain []byte
	switch version {
	case 2:
		h := md5.New()
		h.Write(bootKey[:])
		for i := 0; i < 1000; i++ {
			h.Write(salt)
		}
		key := h.Sum(nil)
		stream, err := rc4.NewCipher(key)
		if err != nil {
			return nil, version, err
		}
		plain = make([]byte, len(data)-24)
		stream.XORKeyStream(plain, data[24:])
	case 3:
		ciphertext := data[24:]
		if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
			return nil, version, fmt.Errorf("%w: PEK AES length", ErrMalformedRecord)
		}
		block, err := aes.NewCipher(bootKey[:])
		if err != nil {
			return nil, version, err
		}
		plain = make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, salt).CryptBlocks(plain, ciphertext)
	default:
		return nil, version, fmt.Errorf("%w: PEK version %d", ErrUnsupportedRevision, version)
	}
	if len(plain) < 52 {
		return nil, version, fmt.Errorf("%w: PEK plaintext", ErrMalformedRecord)
	}
	entries := (len(plain) - 32) / 20
	if entries < 1 || entries > maxPEKEntries {
		return nil, version, fmt.Errorf("%w: PEK entries", ErrMalformedRecord)
	}
	peks := make(map[uint32][]byte, entries)
	for i := 0; i < entries; i++ {
		offset := 32 + i*20
		index := binary.LittleEndian.Uint32(plain[offset : offset+4])
		if index != uint32(i) {
			break
		}
		peks[index] = append([]byte(nil), plain[offset+4:offset+20]...)
	}
	if len(peks) == 0 {
		return nil, version, fmt.Errorf("%w: PEK entries", ErrMalformedRecord)
	}
	return peks, version, nil
}

func clearPEKs(peks map[uint32][]byte) {
	for _, pek := range peks {
		clearBytes(pek)
	}
}

func encryptedPEKIndex(data []byte) uint32 {
	if len(data) < 8 {
		return ^uint32(0)
	}
	return binary.LittleEndian.Uint32(data[4:8])
}

func decryptCurrentHash(data, pek []byte, rid uint32) ([]byte, error) {
	if len(pek) != 16 || len(data) < 24 {
		return nil, ErrMalformedRecord
	}
	version := binary.LittleEndian.Uint32(data[:4])
	var encrypted []byte
	switch version {
	case 1:
		keyMaterial := data[8:24]
		h := md5.New()
		h.Write(pek)
		h.Write(keyMaterial)
		stream, err := rc4.NewCipher(h.Sum(nil))
		if err != nil {
			return nil, err
		}
		encrypted = make([]byte, len(data)-24)
		stream.XORKeyStream(encrypted, data[24:])
	case 0x13:
		if len(data) < 44 || (len(data)-28)%aes.BlockSize != 0 {
			return nil, ErrMalformedRecord
		}
		block, err := aes.NewCipher(pek)
		if err != nil {
			return nil, err
		}
		encrypted = make([]byte, len(data)-28)
		cipher.NewCBCDecrypter(block, data[8:24]).CryptBlocks(encrypted, data[28:])
	default:
		return nil, fmt.Errorf("%w: hash version %d", ErrUnsupportedRevision, version)
	}
	if len(encrypted) < 16 {
		return nil, ErrMalformedRecord
	}
	return decryptRID(encrypted[:16], rid)
}

func decryptRID(input []byte, rid uint32) ([]byte, error) {
	if len(input) != 16 {
		return nil, ErrMalformedRecord
	}
	b := [4]byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	keys := [2][8]byte{expandDES([7]byte{b[0], b[1], b[2], b[3], b[0], b[1], b[2]}), expandDES([7]byte{b[3], b[0], b[1], b[2], b[3], b[0], b[1]})}
	out := make([]byte, 16)
	for i := range keys {
		block, err := des.NewCipher(keys[i][:])
		if err != nil {
			return nil, err
		}
		block.Decrypt(out[i*8:(i+1)*8], input[i*8:(i+1)*8])
	}
	return out, nil
}

func expandDES(in [7]byte) [8]byte {
	out := [8]byte{in[0] >> 1, (in[0]&1)<<6 | in[1]>>2, (in[1]&3)<<5 | in[2]>>3, (in[2]&7)<<4 | in[3]>>4,
		(in[3]&15)<<3 | in[4]>>5, (in[4]&31)<<2 | in[5]>>6, (in[5]&63)<<1 | in[6]>>7, in[6] & 0x7f}
	for i := range out {
		out[i] <<= 1
		out[i] |= 1 ^ (byteOnes(out[i]) & 1)
	}
	return out
}

func byteOnes(value byte) byte {
	var count byte
	for value != 0 {
		count += value & 1
		value >>= 1
	}
	return count
}

func sidString(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	parts := []string{fmt.Sprintf("S-%d-%d", sid[0], binary.BigEndian.Uint64(append([]byte{0, 0}, sid[2:8]...)))}
	count := int(sid[1])
	if count > 15 || 8+4*count > len(sid) {
		return ""
	}
	for i := 0; i < count; i++ {
		parts = append(parts, fmt.Sprintf("%d", binary.BigEndian.Uint32(sid[8+i*4:12+i*4])))
	}
	return strings.Join(parts, "-")
}

func isAccountObject(row *ordereddict.Dict) bool {
	value, ok := row.Get("ATTj590126")
	if !ok {
		return true
	}
	var accountType uint32
	switch typed := value.(type) {
	case int32:
		accountType = uint32(typed)
	case uint32:
		accountType = typed
	case int64:
		accountType = uint32(typed)
	default:
		return true
	}
	return accountType == 0x30000000 || accountType == 0x30000001 || accountType == 0x30000002
}

func userAccountControlDisabled(row *ordereddict.Dict) bool {
	value, ok := row.Get("ATTj589832")
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case int32:
		return uint32(typed)&2 != 0
	case uint32:
		return typed&2 != 0
	case int64:
		return uint64(typed)&2 != 0
	}
	return false
}

package ntdsparse

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

func TestDecryptPEKVersion2AndCurrentHash(t *testing.T) {
	var boot [16]byte
	for i := range boot {
		boot[i] = byte(i + 1)
	}
	var expectedPEK [16]byte
	for i := range expectedPEK {
		expectedPEK[i] = byte(0xa0 + i)
	}
	salt := []byte("0123456789abcdef")
	plain := make([]byte, 52)
	binary.LittleEndian.PutUint32(plain[32:36], 0)
	copy(plain[36:52], expectedPEK[:])
	pekBlob := append([]byte{2, 0, 0, 0, 0, 0, 0, 0}, salt...)
	keyHash := md5.New()
	keyHash.Write(boot[:])
	for i := 0; i < 1000; i++ {
		keyHash.Write(salt)
	}
	stream, err := rc4.NewCipher(keyHash.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)
	pekBlob = append(pekBlob, ciphertext...)
	pek, revision, err := decryptPEK(pekBlob, boot)
	if err != nil || revision != 2 || string(pek) != string(expectedPEK[:]) {
		t.Fatalf("PEK decode revision=%d length=%d err=%v", revision, len(pek), err)
	}

	rid := uint32(1107)
	clear := []byte("0123456789abcdef")
	keys := ridKeysForTest(rid)
	rib := make([]byte, 16)
	for i := range keys {
		block, err := des.NewCipher(keys[i][:])
		if err != nil {
			t.Fatal(err)
		}
		block.Encrypt(rib[i*8:(i+1)*8], clear[i*8:(i+1)*8])
	}
	material := []byte("fedcba9876543210")
	h := md5.New()
	h.Write(pek)
	h.Write(material)
	stream, err = rc4.NewCipher(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	outer := make([]byte, len(rib))
	stream.XORKeyStream(outer, rib)
	hashBlob := append([]byte{1, 0, 0, 0, 0, 0, 0, 0}, material...)
	hashBlob = append(hashBlob, outer...)
	decoded, err := decryptCurrentHash(hashBlob, pek, rid)
	if err != nil || string(decoded) != string(clear) {
		t.Fatalf("hash decode length=%d err=%v", len(decoded), err)
	}
}

func TestNTDSBoundsAndSafeSerialization(t *testing.T) {
	var boot [16]byte
	if _, _, err := decryptPEK(make([]byte, 23), boot); err == nil {
		t.Fatal("short PEK accepted")
	}
	if _, err := decryptCurrentHash(make([]byte, 23), make([]byte, 16), 1); err == nil {
		t.Fatal("short hash accepted")
	}
	if _, err := Parse(Input{Reader: bytesReader([]byte("not ESE")), Size: 7}); err == nil {
		t.Fatal("invalid ESE accepted")
	}
	data, err := json.Marshal(Account{SamAccountName: "synthetic", CurrentNTHashPresent: true, ntHash: [16]byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || containsAny(string(data), "010203") {
		t.Fatal("hash material serialized")
	}
}

func TestEncryptedPEKIndexUsesHeaderDWORD(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[4:8], 7)
	data[8] = 0xa5
	if got := encryptedPEKIndex(data); got != 7 {
		t.Fatalf("PEK index=%d, want header index 7", got)
	}
}

type byteReader []byte

func (r byteReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r)) {
		return 0, io.EOF
	}
	n := copy(p, r[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func bytesReader(value []byte) byteReader { return byteReader(value) }

func containsAny(value string, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func ridKeysForTest(rid uint32) [2][8]byte {
	b := [4]byte{byte(rid), byte(rid >> 8), byte(rid >> 16), byte(rid >> 24)}
	return [2][8]byte{expandDES([7]byte{b[0], b[1], b[2], b[3], b[0], b[1], b[2]}), expandDES([7]byte{b[3], b[0], b[1], b[2], b[3], b[0], b[1]})}
}

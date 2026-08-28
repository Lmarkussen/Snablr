package testfixture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
)

// SAMAccount describes one synthetic local account. NTHash is supplied by the
// test as an independently calculated expected vector.
type SAMAccount struct {
	RID          uint32
	Username     string
	NTHash       [16]byte
	HashRevision uint16
	Enabled      *bool
}

// SAMSpec controls deterministic synthetic SAM generation.
type SAMSpec struct {
	BootKey       [16]byte
	KeyRevision   uint32
	IncludeDomain bool
	Accounts      []SAMAccount
}

// BuildSAM creates a valid synthetic SAM-shaped hive without real credentials.
func BuildSAM(spec SAMSpec) []byte {
	b := &builder{b: make([]byte, base+bins), next: 0x20}
	copy(b.b[:4], "regf")
	binary.LittleEndian.PutUint32(b.b[20:], 1)
	binary.LittleEndian.PutUint32(b.b[24:], 5)
	copy(b.b[base:base+4], "hbin")
	binary.LittleEndian.PutUint32(b.b[base+8:], bins)
	root := b.nk("SAM")
	domains, account, users := b.nk("Domains"), b.nk("Account"), b.nk("Users")
	if spec.IncludeDomain {
		b.setChildren(root, []uint32{domains})
		b.setChildren(domains, []uint32{account})
		b.setChildren(account, []uint32{users})
	}
	samKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	f := make([]byte, 0x70)
	binary.LittleEndian.PutUint32(f[0:], 3)
	keyData := makeSAMKey(spec.KeyRevision, samKey, spec.BootKey)
	f = append(f, keyData...)
	fValue := b.vk("F", 3, f)
	b.setValues(account, 1, b.valueList(fValue))
	children := []uint32{}
	for _, accountSpec := range spec.Accounts {
		user := b.nk(formatRID(accountSpec.RID))
		v := makeV(accountSpec, samKey)
		vValue := b.vk("V", 3, v)
		values := []uint32{vValue}
		if accountSpec.Enabled != nil {
			values = append(values, b.vk("F", 3, userF(*accountSpec.Enabled)))
		}
		b.setValues(user, uint32(len(values)), b.valueList(values...))
		children = append(children, user)
	}
	// Names is intentionally present to verify that RID enumeration ignores it.
	children = append(children, b.nk("Names"))
	b.setChildren(users, children)
	if !spec.IncludeDomain {
		b.setChildren(root, nil)
	}
	binary.LittleEndian.PutUint32(b.b[36:], root)
	binary.LittleEndian.PutUint32(b.b[40:], bins)
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(b.b[i:])
	}
	binary.LittleEndian.PutUint32(b.b[508:], checksum)
	return b.b
}

func formatRID(rid uint32) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = hex[rid&15]
		rid >>= 4
	}
	return string(out)
}
func userF(enabled bool) []byte {
	p := make([]byte, 0x3a)
	if !enabled {
		binary.LittleEndian.PutUint16(p[0x38:], 1)
	}
	return p
}

var samQwerty = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
var samDigits = []byte("0123456789012345678901234567890123456789\x00")

func makeSAMKey(revision uint32, samKey, boot [16]byte) []byte {
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if revision == 1 {
		p := make([]byte, 64)
		binary.LittleEndian.PutUint32(p[0:], 1)
		binary.LittleEndian.PutUint32(p[4:], 64)
		copy(p[8:], salt[:])
		copy(p[24:], samKey[:])
		check := md5.Sum(append(append(append([]byte{}, samKey[:]...), samDigits...), append(samKey[:], samQwerty...)...))
		copy(p[40:], check[:])
		h := md5.New()
		h.Write(salt[:])
		h.Write(samQwerty)
		h.Write(boot[:])
		h.Write(samDigits)
		c, _ := rc4.NewCipher(h.Sum(nil))
		c.XORKeyStream(p[24:56], p[24:56])
		return p
	}
	if revision != 2 {
		p := make([]byte, 8)
		binary.LittleEndian.PutUint32(p, revision)
		return p
	}
	plainCheck := sha256.Sum256(samKey[:])
	p := make([]byte, 0x20+16+32)
	binary.LittleEndian.PutUint32(p[0:], 2)
	binary.LittleEndian.PutUint32(p[4:], uint32(len(p)))
	binary.LittleEndian.PutUint32(p[8:], 32)
	binary.LittleEndian.PutUint32(p[12:], 16)
	copy(p[16:], salt[:])
	block, _ := aes.NewCipher(boot[:])
	cipher.NewCBCEncrypter(block, salt[:]).CryptBlocks(p[32:48], samKey[:])
	cipher.NewCBCEncrypter(block, salt[:]).CryptBlocks(p[48:80], plainCheck[:])
	return p
}

func makeV(a SAMAccount, samKey [16]byte) []byte {
	p := make([]byte, 0xcc)
	name := utf16BytesSAM(a.Username)
	binary.LittleEndian.PutUint32(p[0x0c:], 0)
	binary.LittleEndian.PutUint32(p[0x10:], uint32(len(name)))
	p = append(p, name...)
	for len(p)%4 != 0 {
		p = append(p, 0)
	}
	desData := desEncrypt(a.NTHash, a.RID)
	hash := make([]byte, 0)
	if a.HashRevision == 0 {
		a.HashRevision = 1
	}
	if a.HashRevision == 1 {
		hash = make([]byte, 20)
		binary.LittleEndian.PutUint16(hash[2:], 1)
		h := md5.New()
		h.Write(samKey[:])
		var rid [4]byte
		binary.LittleEndian.PutUint32(rid[:], a.RID)
		h.Write(rid[:])
		h.Write([]byte("NTPASSWORD\x00"))
		c, _ := rc4.NewCipher(h.Sum(nil))
		c.XORKeyStream(hash[4:], desData)
	} else if a.HashRevision == 2 {
		salt := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30}
		enc := make([]byte, 16)
		block, _ := aes.NewCipher(samKey[:])
		cipher.NewCBCEncrypter(block, salt).CryptBlocks(enc, desData)
		hash = make([]byte, 40)
		binary.LittleEndian.PutUint16(hash[2:], 2)
		binary.LittleEndian.PutUint32(hash[4:], 1)
		copy(hash[8:], salt)
		copy(hash[24:], enc)
	} else {
		hash = make([]byte, 20)
		binary.LittleEndian.PutUint16(hash[2:], a.HashRevision)
	}
	off := uint32(len(p) - 0xcc)
	binary.LittleEndian.PutUint32(p[0xa8:], off)
	binary.LittleEndian.PutUint32(p[0xac:], uint32(len(hash)))
	p = append(p, hash...)
	return p
}

func desEncrypt(hash [16]byte, rid uint32) []byte {
	keys := ridKeys(rid)
	out := make([]byte, 16)
	c1, _ := des.NewCipher(keys[0][:])
	c2, _ := des.NewCipher(keys[1][:])
	c1.Encrypt(out[:8], hash[:8])
	c2.Encrypt(out[8:], hash[8:])
	return out
}
func ridKeys(rid uint32) [2][8]byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], rid)
	return [2][8]byte{expand([7]byte{b[0], b[1], b[2], b[3], b[0], b[1], b[2]}), expand([7]byte{b[3], b[0], b[1], b[2], b[3], b[0], b[1]})}
}
func expand(in [7]byte) [8]byte {
	var o [8]byte
	o[0] = in[0] >> 1
	o[1] = (in[0]&1)<<6 | in[1]>>2
	o[2] = (in[1]&3)<<5 | in[2]>>3
	o[3] = (in[2]&7)<<4 | in[3]>>4
	o[4] = (in[3]&15)<<3 | in[4]>>5
	o[5] = (in[4]&31)<<2 | in[5]>>6
	o[6] = (in[5]&63)<<1 | in[6]>>7
	o[7] = in[6] & 127
	for i := range o {
		o[i] <<= 1
		o[i] |= 1 - (ones(o[i]) & 1)
	}
	return o
}
func ones(v byte) byte {
	n := byte(0)
	for v != 0 {
		n += v & 1
		v >>= 1
	}
	return n
}
func utf16BytesSAM(s string) []byte {
	r := []byte{}
	for _, u := range encodeSAM(s) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], u)
		r = append(r, b[:]...)
	}
	return r
}
func encodeSAM(s string) []uint16 {
	out := []uint16{}
	for _, r := range s {
		if r <= 0xffff {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		}
	}
	return out
}

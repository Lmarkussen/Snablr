// Package registryhive provides a bounded, read-only reader for Windows REGF
// registry hives. It deliberately knows nothing about WIMs, SMB, or secrets.
package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf16"
)

var (
	ErrMalformed          = errors.New("malformed registry hive")
	ErrUnsupportedVersion = errors.New("unsupported registry hive version")
	ErrTruncated          = errors.New("truncated registry hive")
	ErrInvalidOffset      = errors.New("invalid registry hive offset")
	ErrValueTooLarge      = errors.New("registry value exceeds configured limit")
	ErrKeyNotFound        = errors.New("registry key not found")
	ErrValueNotFound      = errors.New("registry value not found")
	ErrInvalidUTF16       = errors.New("invalid UTF-16 registry data")
)

const (
	RegNone         uint32 = 0
	RegSZ           uint32 = 1
	RegExpandSZ     uint32 = 2
	RegBinary       uint32 = 3
	RegDWORD        uint32 = 4
	RegDWORDBE      uint32 = 5
	RegMultiSZ      uint32 = 7
	RegQWORD        uint32 = 11
	keyCompressed   uint16 = 0x20
	valueCompressed uint16 = 0x01
	baseBlockSize          = 4096
	maxCellBytes           = 16 << 20
	maxBins                = 1 << 20
)

// Options bounds all allocations and traversals performed by Reader.
type Options struct {
	MaxValueBytes      int64
	MaxSubkeysPerKey   uint32
	MaxValuesPerKey    uint32
	MaxTraversalDepth  uint32
	MaxBigDataSegments uint32
}

func defaultOptions(o Options) Options {
	if o.MaxValueBytes <= 0 {
		o.MaxValueBytes = 4 << 20
	}
	if o.MaxSubkeysPerKey == 0 {
		o.MaxSubkeysPerKey = 4096
	}
	if o.MaxValuesPerKey == 0 {
		o.MaxValuesPerKey = 4096
	}
	if o.MaxTraversalDepth == 0 {
		o.MaxTraversalDepth = 64
	}
	if o.MaxBigDataSegments == 0 {
		o.MaxBigDataSegments = 1024
	}
	return o
}

type bin struct{ rel, size uint32 }

// Reader is a read-only view over a registry hive backed by ReaderAt.
type Reader struct {
	src            io.ReaderAt
	size, hiveSize int64
	root           uint32
	opts           Options
	bins           []bin
}

// Open validates the hive base block and all HBIN headers before returning a reader.
func Open(src io.ReaderAt, size int64, opts Options) (*Reader, error) {
	if src == nil || size < baseBlockSize {
		return nil, fmt.Errorf("%w: base block", ErrTruncated)
	}
	if opts.MaxValueBytes < 0 {
		return nil, fmt.Errorf("%w: negative value limit", ErrMalformed)
	}
	o := defaultOptions(opts)
	h := make([]byte, baseBlockSize)
	if err := readAt(src, h, 0, size); err != nil {
		return nil, err
	}
	if string(h[:4]) != "regf" {
		return nil, fmt.Errorf("%w: base block signature", ErrMalformed)
	}
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(h[i:])
	}
	if binary.LittleEndian.Uint32(h[508:]) != checksum {
		return nil, fmt.Errorf("%w: base block checksum", ErrMalformed)
	}
	major, minor := binary.LittleEndian.Uint32(h[20:24]), binary.LittleEndian.Uint32(h[24:28])
	if major != 1 || minor < 3 || minor > 6 {
		return nil, fmt.Errorf("%w: %d.%d", ErrUnsupportedVersion, major, minor)
	}
	root := binary.LittleEndian.Uint32(h[36:40])
	hiveData := binary.LittleEndian.Uint32(h[40:44])
	if hiveData == 0 || hiveData%4096 != 0 {
		return nil, fmt.Errorf("%w: hive bin extent", ErrMalformed)
	}
	extent, ok := addInt64(baseBlockSize, int64(hiveData))
	if !ok || extent > size {
		return nil, fmt.Errorf("%w: hive extent", ErrTruncated)
	}
	if root >= hiveData || root%8 != 0 {
		return nil, fmt.Errorf("%w: root cell", ErrInvalidOffset)
	}
	r := &Reader{src: src, size: size, hiveSize: int64(hiveData), root: root, opts: o}
	for rel := uint32(0); rel < hiveData; {
		if len(r.bins) >= maxBins {
			return nil, fmt.Errorf("%w: too many hive bins", ErrValueTooLarge)
		}
		if hiveData-rel < 32 {
			return nil, fmt.Errorf("%w: short hbin header", ErrTruncated)
		}
		b := make([]byte, 32)
		if err := readAt(src, b, baseBlockSize+int64(rel), size); err != nil {
			return nil, err
		}
		if string(b[:4]) != "hbin" {
			return nil, fmt.Errorf("%w: hbin at %#x", ErrMalformed, rel)
		}
		if binary.LittleEndian.Uint32(b[4:8]) != rel {
			return nil, fmt.Errorf("%w: hbin relative offset", ErrMalformed)
		}
		bs := binary.LittleEndian.Uint32(b[8:12])
		if bs < 32 || bs%4096 != 0 {
			return nil, fmt.Errorf("%w: hbin size", ErrMalformed)
		}
		end, ok := addUint32(rel, bs)
		if !ok || end > hiveData {
			return nil, fmt.Errorf("%w: hbin bounds", ErrInvalidOffset)
		}
		r.bins = append(r.bins, bin{rel: rel, size: bs})
		rel = end
	}
	return r, nil
}

func addInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}
func addUint32(a, b uint32) (uint32, bool) {
	if b > math.MaxUint32-a {
		return 0, false
	}
	return a + b, true
}

func readAt(src io.ReaderAt, p []byte, off, size int64) error {
	if off < 0 || int64(len(p)) > size-off {
		return fmt.Errorf("%w: read range", ErrTruncated)
	}
	n, err := src.ReadAt(p, off)
	if err != nil || n != len(p) {
		return fmt.Errorf("%w: read range", ErrTruncated)
	}
	return nil
}

func (r *Reader) binFor(rel uint32) (bin, bool) {
	for _, b := range r.bins {
		if rel >= b.rel && rel < b.rel+b.size {
			return b, true
		}
	}
	return bin{}, false
}

type cell struct {
	rel       uint32
	allocated bool
	data      []byte
	binEnd    uint32
}

func (r *Reader) cellAt(rel uint32) (cell, error) {
	b, ok := r.binFor(rel)
	if !ok || rel%8 != 0 {
		return cell{}, fmt.Errorf("%w: cell %#x", ErrInvalidOffset, rel)
	}
	abs, ok := addInt64(baseBlockSize, int64(rel))
	if !ok || abs+4 > r.size {
		return cell{}, fmt.Errorf("%w: cell header", ErrTruncated)
	}
	h := make([]byte, 4)
	if err := readAt(r.src, h, abs, r.size); err != nil {
		return cell{}, err
	}
	sz := int32(binary.LittleEndian.Uint32(h))
	if sz == 0 || sz == math.MinInt32 {
		return cell{}, fmt.Errorf("%w: cell size", ErrMalformed)
	}
	allocated := sz < 0
	total := int64(sz)
	if total < 0 {
		total = -total
	}
	if total < 8 || total%8 != 0 || total > maxCellBytes {
		return cell{}, fmt.Errorf("%w: cell size", ErrMalformed)
	}
	end, ok := addUint32(rel, uint32(total))
	if !ok || end > b.rel+b.size || end > uint32(r.hiveSize) {
		return cell{}, fmt.Errorf("%w: cell bounds", ErrInvalidOffset)
	}
	dataLen := int(total) - 4
	data := make([]byte, dataLen)
	if err := readAt(r.src, data, abs+4, r.size); err != nil {
		return cell{}, err
	}
	return cell{rel: rel, allocated: allocated, data: data, binEnd: b.rel + b.size}, nil
}

func u16(p []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(p) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(p[off:]), true
}
func u32(p []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(p) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p[off:]), true
}

// Key is a read-only registry key handle.
type Key struct {
	r    *Reader
	rel  uint32
	path string
	nk   nkInfo
}
type nkInfo struct {
	name                                                    string
	flags                                                   uint16
	parent, subCount, subList, valueCount, valueList, class uint32
	classLen, nameLen                                       uint16
}

func (r *Reader) nkAt(rel uint32) (Key, error) {
	c, err := r.cellAt(rel)
	if err != nil {
		return Key{}, err
	}
	if !c.allocated || len(c.data) < 0x50 || string(c.data[:2]) != "nk" {
		return Key{}, fmt.Errorf("%w: NK cell", ErrMalformed)
	}
	flags, _ := u16(c.data, 2)
	parent, _ := u32(c.data, 16)
	subCount, _ := u32(c.data, 20)
	subList, _ := u32(c.data, 28)
	valCount, _ := u32(c.data, 36)
	valList, _ := u32(c.data, 40)
	class, _ := u32(c.data, 48)
	nameLen, _ := u16(c.data, 76)
	classLen, _ := u16(c.data, 78)
	end := 0x50 + int(nameLen)
	if end > len(c.data) {
		return Key{}, fmt.Errorf("%w: NK name", ErrTruncated)
	}
	name, err := decodeName(c.data[0x50:end], flags&keyCompressed != 0)
	if err != nil {
		return Key{}, err
	}
	return Key{r: r, rel: rel, nk: nkInfo{name: name, flags: flags, parent: parent, subCount: subCount, subList: subList, valueCount: valCount, valueList: valList, class: class, classLen: classLen, nameLen: nameLen}}, nil
}

func (r *Reader) OpenKey(path string) (*Key, error) {
	path = normalizePath(path)
	k, err := r.nkAt(r.root)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return &k, nil
	}
	for _, part := range strings.Split(path, `\`) {
		next, found, err := k.child(part)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, part)
		}
		k = next
	}
	return &k, nil
}
func normalizePath(p string) string { p = strings.ReplaceAll(p, "/", `\`); return strings.Trim(p, `\`) }
func (k *Key) Name() string         { return k.nk.name }
func (k *Key) Flags() uint16        { return k.nk.flags }

func (k *Key) child(want string) (Key, bool, error) {
	refs, err := k.r.subkeyRefs(k.nk.subList, k.nk.subCount, 0, map[uint32]bool{})
	if err != nil {
		return Key{}, false, err
	}
	for _, rel := range refs {
		child, err := k.r.nkAt(rel)
		if err != nil {
			return Key{}, false, err
		}
		if strings.EqualFold(child.nk.name, want) {
			child.path = want
			return child, true, nil
		}
	}
	return Key{}, false, nil
}

func (k *Key) Subkeys() ([]string, error) {
	refs, err := k.r.subkeyRefs(k.nk.subList, k.nk.subCount, 0, map[uint32]bool{})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, rel := range refs {
		c, e := k.r.nkAt(rel)
		if e != nil {
			return nil, e
		}
		key := strings.ToLower(c.nk.name)
		if !seen[key] {
			seen[key] = true
			out = append(out, c.nk.name)
		}
	}
	return out, nil
}

func (r *Reader) subkeyRefs(rel uint32, expected, depth uint32, active map[uint32]bool) ([]uint32, error) {
	if expected == 0 {
		return nil, nil
	}
	if expected > r.opts.MaxSubkeysPerKey {
		return nil, fmt.Errorf("%w: subkey count", ErrValueTooLarge)
	}
	if depth > r.opts.MaxTraversalDepth {
		return nil, fmt.Errorf("%w: subkey depth", ErrMalformed)
	}
	if active[rel] {
		return nil, fmt.Errorf("%w: cyclic subkey index", ErrMalformed)
	}
	active[rel] = true
	defer delete(active, rel)
	c, err := r.cellAt(rel)
	if err != nil {
		return nil, err
	}
	if !c.allocated || len(c.data) < 4 {
		return nil, fmt.Errorf("%w: subkey list", ErrMalformed)
	}
	sig := string(c.data[:2])
	count := uint32(binary.LittleEndian.Uint16(c.data[2:4]))
	if count > r.opts.MaxSubkeysPerKey {
		return nil, fmt.Errorf("%w: subkey index count", ErrValueTooLarge)
	}
	if sig == "lf" || sig == "lh" {
		if int(4+count*8) > len(c.data) {
			return nil, fmt.Errorf("%w: subkey index entries", ErrTruncated)
		}
		out := make([]uint32, 0, count)
		for i := uint32(0); i < count; i++ {
			v := binary.LittleEndian.Uint32(c.data[4+i*8:])
			out = append(out, v)
		}
		return out, nil
	}
	if sig == "li" {
		if int(4+count*4) > len(c.data) {
			return nil, fmt.Errorf("%w: li entries", ErrTruncated)
		}
		out := make([]uint32, 0, count)
		for i := uint32(0); i < count; i++ {
			out = append(out, binary.LittleEndian.Uint32(c.data[4+i*4:]))
		}
		return out, nil
	}
	if sig == "ri" {
		if int(4+count*4) > len(c.data) {
			return nil, fmt.Errorf("%w: ri entries", ErrTruncated)
		}
		out := []uint32{}
		for i := uint32(0); i < count; i++ {
			part, e := r.subkeyRefs(binary.LittleEndian.Uint32(c.data[4+i*4:]), expected, depth+1, active)
			if e != nil {
				return nil, e
			}
			if uint32(len(out))+uint32(len(part)) > r.opts.MaxSubkeysPerKey {
				return nil, fmt.Errorf("%w: subkey count", ErrValueTooLarge)
			}
			out = append(out, part...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: unknown subkey index", ErrMalformed)
}

// ClassName returns the NK class metadata used by some Windows hives.
func (k *Key) ClassName() (string, error) {
	if k.nk.class == 0 || k.nk.classLen == 0 {
		return "", nil
	}
	c, e := k.r.cellAt(k.nk.class)
	if e != nil {
		return "", e
	}
	if !c.allocated || int(k.nk.classLen) > len(c.data) {
		return "", fmt.Errorf("%w: class data", ErrTruncated)
	}
	return decodeUTF16(c.data[:k.nk.classLen])
}

type Value struct {
	Name string
	Type uint32
	Raw  []byte
}

func (k *Key) Value(name string) (Value, error) {
	vals, e := k.Values()
	if e != nil {
		return Value{}, e
	}
	for _, v := range vals {
		if strings.EqualFold(v.Name, name) {
			return v, nil
		}
	}
	return Value{}, fmt.Errorf("%w: %s", ErrValueNotFound, name)
}
func (k *Key) Values() ([]Value, error) {
	if k.nk.valueCount > k.r.opts.MaxValuesPerKey {
		return nil, fmt.Errorf("%w: value count", ErrValueTooLarge)
	}
	if k.nk.valueCount == 0 {
		return nil, nil
	}
	c, e := k.r.cellAt(k.nk.valueList)
	if e != nil {
		return nil, e
	}
	if !c.allocated || uint64(k.nk.valueCount)*4 > uint64(len(c.data)) {
		return nil, fmt.Errorf("%w: value list", ErrTruncated)
	}
	out := make([]Value, 0, k.nk.valueCount)
	for i := uint32(0); i < k.nk.valueCount; i++ {
		v, e := k.r.valueAt(binary.LittleEndian.Uint32(c.data[i*4:]))
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r *Reader) valueAt(rel uint32) (Value, error) {
	c, e := r.cellAt(rel)
	if e != nil {
		return Value{}, e
	}
	if !c.allocated || len(c.data) < 0x14 || string(c.data[:2]) != "vk" {
		return Value{}, fmt.Errorf("%w: VK cell", ErrMalformed)
	}
	nl, _ := u16(c.data, 2)
	dl, _ := u32(c.data, 4)
	do, _ := u32(c.data, 8)
	typ, _ := u32(c.data, 12)
	flags, _ := u16(c.data, 16)
	end := 0x14 + int(nl)
	if end > len(c.data) {
		return Value{}, fmt.Errorf("%w: VK name", ErrTruncated)
	}
	name, e := decodeName(c.data[0x14:end], flags&valueCompressed != 0)
	if e != nil {
		return Value{}, e
	}
	rawlen := uint64(dl & 0x7fffffff)
	if rawlen > uint64(r.opts.MaxValueBytes) {
		return Value{}, fmt.Errorf("%w: value", ErrValueTooLarge)
	}
	raw, e := r.valueData(do, rawlen, dl&0x80000000 != 0)
	if e != nil {
		return Value{}, e
	}
	return Value{Name: name, Type: typ, Raw: raw}, nil
}
func (r *Reader) valueData(off uint32, n uint64, inline bool) ([]byte, error) {
	if inline {
		if n > 4 {
			return nil, fmt.Errorf("%w: inline value", ErrMalformed)
		}
		b := make([]byte, n)
		var t [4]byte
		binary.LittleEndian.PutUint32(t[:], off)
		copy(b, t[:n])
		return b, nil
	}
	if n == 0 {
		return []byte{}, nil
	}
	c, e := r.cellAt(off)
	if e != nil {
		return nil, e
	}
	if !c.allocated {
		return nil, fmt.Errorf("%w: free value data", ErrMalformed)
	}
	if len(c.data) >= 4 && string(c.data[:2]) == "db" {
		return r.bigData(c, n)
	}
	if n > uint64(len(c.data)) {
		return nil, fmt.Errorf("%w: value data", ErrTruncated)
	}
	b := make([]byte, n)
	copy(b, c.data[:n])
	return b, nil
}
func (r *Reader) bigData(db cell, n uint64) ([]byte, error) {
	if len(db.data) < 8 {
		return nil, fmt.Errorf("%w: big data header", ErrTruncated)
	}
	count := uint32(binary.LittleEndian.Uint16(db.data[2:]))
	list := binary.LittleEndian.Uint32(db.data[4:])
	if count == 0 || count > r.opts.MaxBigDataSegments {
		return nil, fmt.Errorf("%w: big data segments", ErrValueTooLarge)
	}
	c, e := r.cellAt(list)
	if e != nil {
		return nil, e
	}
	if uint64(count)*4 > uint64(len(c.data)) {
		return nil, fmt.Errorf("%w: big data list", ErrTruncated)
	}
	out := make([]byte, 0, n)
	for i := uint32(0); i < count && uint64(len(out)) < n; i++ {
		s, e := r.cellAt(binary.LittleEndian.Uint32(c.data[i*4:]))
		if e != nil {
			return nil, e
		}
		take := uint64(len(s.data))
		if take > n-uint64(len(out)) {
			take = n - uint64(len(out))
		}
		out = append(out, s.data[:take]...)
	}
	if uint64(len(out)) < n {
		return nil, fmt.Errorf("%w: big data segments", ErrTruncated)
	}
	return out, nil
}

func decodeName(b []byte, compressed bool) (string, error) {
	if compressed {
		return string(b), nil
	}
	return decodeUTF16(b)
}
func decodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: odd byte length", ErrInvalidUTF16)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: surrogate", ErrInvalidUTF16)
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", fmt.Errorf("%w: surrogate", ErrInvalidUTF16)
		}
	}
	return string(utf16.Decode(u)), nil
}

func (v Value) Bytes() []byte { return append([]byte(nil), v.Raw...) }
func (v Value) StringValue() (string, error) {
	if v.Type != RegSZ && v.Type != RegExpandSZ {
		return "", fmt.Errorf("%w: value type", ErrMalformed)
	}
	s, e := decodeUTF16(v.Raw)
	return strings.TrimRight(s, "\x00"), e
}
func (v Value) Strings() ([]string, error) {
	if v.Type != RegMultiSZ {
		return nil, fmt.Errorf("%w: value type", ErrMalformed)
	}
	s, e := decodeUTF16(v.Raw)
	if e != nil {
		return nil, e
	}
	if !strings.HasSuffix(s, "\x00\x00") {
		return nil, fmt.Errorf("%w: unterminated multi-string", ErrMalformed)
	}
	parts := strings.Split(strings.TrimRight(s, "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return nil, nil
	}
	return parts, nil
}
func (v Value) DWORD() (uint32, error) {
	if v.Type != RegDWORD && v.Type != RegDWORDBE || len(v.Raw) != 4 {
		return 0, fmt.Errorf("%w: DWORD value", ErrMalformed)
	}
	if v.Type == RegDWORDBE {
		return binary.BigEndian.Uint32(v.Raw), nil
	}
	return binary.LittleEndian.Uint32(v.Raw), nil
}
func (v Value) QWORD() (uint64, error) {
	if v.Type != RegQWORD || len(v.Raw) != 8 {
		return 0, fmt.Errorf("%w: QWORD value", ErrMalformed)
	}
	return binary.LittleEndian.Uint64(v.Raw), nil
}

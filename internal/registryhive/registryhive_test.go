package registryhive

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

type fixture struct {
	b                                          []byte
	root, rootList, values, badValue, bigValue uint32
}

type hiveBuilder struct {
	b    []byte
	next uint32
}

func newBuilder() *hiveBuilder {
	const bins = 0x20000
	b := make([]byte, baseBlockSize+bins)
	copy(b[:4], "regf")
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[24:], 5)
	binary.LittleEndian.PutUint32(b[baseBlockSize:], 0) // HBIN relative offset
	binary.LittleEndian.PutUint32(b[baseBlockSize+8:], bins)
	copy(b[baseBlockSize:baseBlockSize+4], "hbin")
	return &hiveBuilder{b: b, next: 0x20}
}

func (h *hiveBuilder) cell(payload []byte) uint32 {
	total := (4 + len(payload) + 7) &^ 7
	rel := h.next
	h.next += uint32(total)
	binary.LittleEndian.PutUint32(h.b[baseBlockSize+int(rel):], uint32(-int32(total)))
	copy(h.b[baseBlockSize+int(rel)+4:], payload)
	return rel
}

func (h *hiveBuilder) data(rel uint32) []byte {
	cell, _ := h.cellAt(rel)
	return h.b[baseBlockSize+int(rel)+4 : baseBlockSize+int(rel)+4+cell]
}

func (h *hiveBuilder) cellAt(rel uint32) (int, bool) {
	if int(rel)+4+baseBlockSize > len(h.b) {
		return 0, false
	}
	sz := int32(binary.LittleEndian.Uint32(h.b[baseBlockSize+int(rel):]))
	if sz >= 0 {
		return 0, false
	}
	return int(-sz) - 4, true
}

func utf16Bytes(s string) []byte {
	r := []byte{}
	for _, u := range utf16.Encode([]rune(s)) {
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], u)
		r = append(r, x[:]...)
	}
	return r
}

func (h *hiveBuilder) nk(name string, compressed bool, class string) uint32 {
	n := []byte(name)
	flags := uint16(0)
	if compressed {
		flags |= keyCompressed
	}
	if !compressed {
		n = utf16Bytes(name)
	}
	p := make([]byte, 0x50+len(n))
	copy(p, []byte("nk"))
	binary.LittleEndian.PutUint16(p[2:], flags)
	binary.LittleEndian.PutUint16(p[0x4c:], uint16(len(n)))
	classBytes := utf16Bytes(class)
	binary.LittleEndian.PutUint16(p[0x4e:], uint16(len(classBytes)))
	copy(p[0x50:], n)
	rel := h.cell(p)
	if len(classBytes) != 0 {
		c := h.cell(classBytes)
		binary.LittleEndian.PutUint32(h.data(rel)[0x30:], c)
	}
	return rel
}

func (h *hiveBuilder) li(children ...uint32) uint32 {
	p := make([]byte, 4+4*len(children))
	copy(p, []byte("li"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(children)))
	for i, child := range children {
		binary.LittleEndian.PutUint32(p[4+i*4:], child)
	}
	return h.cell(p)
}

func (h *hiveBuilder) ri(parts ...uint32) uint32 {
	p := make([]byte, 4+4*len(parts))
	copy(p, []byte("ri"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(parts)))
	for i, part := range parts {
		binary.LittleEndian.PutUint32(p[4+i*4:], part)
	}
	return h.cell(p)
}

func (h *hiveBuilder) setChildren(key, list uint32, count uint32) {
	d := h.data(key)
	binary.LittleEndian.PutUint32(d[20:], count)
	binary.LittleEndian.PutUint32(d[28:], list)
}

func (h *hiveBuilder) vk(name string, typ uint32, raw []byte, inline bool, compressed bool) uint32 {
	n := []byte(name)
	flags := uint16(0)
	if compressed {
		flags |= valueCompressed
	} else {
		n = utf16Bytes(name)
	}
	p := make([]byte, 0x14+len(n))
	copy(p, []byte("vk"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(n)))
	binary.LittleEndian.PutUint32(p[4:], uint32(len(raw))|boolBit(inline))
	binary.LittleEndian.PutUint32(p[12:], typ)
	binary.LittleEndian.PutUint16(p[16:], flags)
	copy(p[0x14:], n)
	if inline {
		var x [4]byte
		copy(x[:], raw)
		binary.LittleEndian.PutUint32(p[8:], binary.LittleEndian.Uint32(x[:]))
	} else {
		d := h.cell(raw)
		binary.LittleEndian.PutUint32(p[8:], d)
	}
	return h.cell(p)
}

func boolBit(v bool) uint32 {
	if v {
		return 0x80000000
	}
	return 0
}

func (h *hiveBuilder) valueList(values ...uint32) uint32 {
	p := make([]byte, len(values)*4)
	for i, v := range values {
		binary.LittleEndian.PutUint32(p[i*4:], v)
	}
	return h.cell(p)
}

func makeFixture() fixture {
	h := newBuilder()
	root := h.nk("ROOT", true, "")
	selectKey := h.nk("Select", true, "")
	cs := h.nk("ControlSet001", true, "")
	control := h.nk("Control", true, "")
	lsa := h.nk("Lsa", true, "")
	jd := h.nk("JD", true, "00112233")
	skew := h.nk("Skew1", true, "44556677")
	gbg := h.nk("GBG", true, "8899aabb")
	data := h.nk("Data", true, "ccddeeff")
	values := h.nk("Values", true, "")
	selectCurrent := h.vk("Current", RegDWORD, []byte{1, 0, 0, 0}, true, true)
	stringValue := h.vk("Greeting", RegSZ, utf16Bytes("hello"+"\x00"), false, true)
	binaryValue := h.vk("Blob", RegBinary, []byte{1, 2, 3, 4, 5}, false, true)
	qwordValue := h.vk("Count", RegQWORD, []byte{8, 7, 6, 5, 4, 3, 2, 1}, false, true)
	multiValue := h.vk("Names", RegMultiSZ, utf16Bytes("one\x00two\x00\x00"), false, true)
	bigData := bytes.Repeat([]byte("Z"), 9000)
	seg1 := h.cell(bigData[:4500])
	seg2 := h.cell(bigData[4500:])
	segmentList := h.valueList(seg1, seg2)
	db := make([]byte, 8)
	copy(db, []byte("db"))
	binary.LittleEndian.PutUint16(db[2:], 2)
	binary.LittleEndian.PutUint32(db[4:], segmentList)
	dbCell := h.cell(db)
	bigVK := h.vk("Large", RegBinary, bigData, false, true)
	// Replace the regular data cell reference with the db cell for the large value.
	bigPayload := h.data(bigVK)
	binary.LittleEndian.PutUint32(bigPayload[8:], dbCell)

	h.setChildren(root, h.ri(h.li(selectKey, cs), h.li(values)), 3)
	h.setChildren(cs, h.li(control), 1)
	h.setChildren(control, h.li(lsa), 1)
	h.setChildren(lsa, h.li(jd, skew, gbg, data), 4)
	binary.LittleEndian.PutUint32(h.data(selectKey)[36:], 1)
	selectList := h.valueList(selectCurrent)
	binary.LittleEndian.PutUint32(h.data(selectKey)[40:], selectList)
	list := h.valueList(stringValue, binaryValue, qwordValue, multiValue, bigVK)
	binary.LittleEndian.PutUint32(h.data(values)[36:], 5)
	binary.LittleEndian.PutUint32(h.data(values)[40:], list)
	binary.LittleEndian.PutUint32(h.b[36:], root)
	binary.LittleEndian.PutUint32(h.b[40:], 0x20000)
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(h.b[i:])
	}
	binary.LittleEndian.PutUint32(h.b[508:], checksum)
	return fixture{b: h.b, root: root, rootList: binary.LittleEndian.Uint32(h.data(root)[28:]), values: values, badValue: bigVK, bigValue: bigVK}
}

func openFixture(t *testing.T) (fixture, *Reader) {
	t.Helper()
	f := makeFixture()
	r, err := Open(bytes.NewReader(f.b), int64(len(f.b)), Options{})
	if err != nil {
		t.Fatalf("Open fixture: %v", err)
	}
	return f, r
}

func TestOpenAndPathLookup(t *testing.T) {
	_, r := openFixture(t)
	k, err := r.OpenKey(`\\controlset001/control/lsa`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := k.Name(), "Lsa"; got != want {
		t.Fatalf("name=%q want %q", got, want)
	}
	subs, err := k.Subkeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 4 {
		t.Fatalf("subkeys=%v", subs)
	}
	for _, name := range []string{"JD", "Skew1", "GBG", "Data"} {
		child, err := r.OpenKey(`ControlSet001\Control\Lsa\` + name)
		if err != nil {
			t.Fatal(err)
		}
		class, err := child.ClassName()
		if err != nil {
			t.Fatal(err)
		}
		if class == "" {
			t.Fatalf("empty class for %s", name)
		}
	}
	if _, err := r.OpenKey("missing"); !errorsIs(err, ErrKeyNotFound) {
		t.Fatalf("missing key error=%v", err)
	}
}

func TestValuesAndDecoders(t *testing.T) {
	_, r := openFixture(t)
	selectKey, err := r.OpenKey("Select")
	if err != nil {
		t.Fatal(err)
	}
	current, err := selectKey.Value("current")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := current.DWORD(); err != nil || n != 1 {
		t.Fatalf("DWORD=%d err=%v", n, err)
	}
	k, err := r.OpenKey("Values")
	if err != nil {
		t.Fatal(err)
	}
	v, err := k.Value("greeting")
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.StringValue()
	if err != nil || s != "hello" {
		t.Fatalf("string=%q err=%v", s, err)
	}
	v, err = k.Value("Current")
	if err == nil {
		t.Fatal("unexpected Current")
	}
	_ = v
	v, err = k.Value("Count")
	if err != nil {
		t.Fatal(err)
	}
	q, err := v.QWORD()
	if err != nil || q != 0x0102030405060708 {
		t.Fatalf("qword=%x err=%v", q, err)
	}
	v, err = k.Value("Names")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := v.Strings()
	if err != nil || len(ss) != 2 || ss[1] != "two" {
		t.Fatalf("multi=%v err=%v", ss, err)
	}
	v, err = k.Value("Large")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Raw) != 9000 || v.Raw[0] != 'Z' {
		t.Fatalf("big value length=%d", len(v.Raw))
	}
	if _, err = k.Value("absent"); !errorsIs(err, ErrValueNotFound) {
		t.Fatalf("missing value error=%v", err)
	}
}

func TestStructuredDecodingRejectsMalformedData(t *testing.T) {
	if _, err := (Value{Type: RegSZ, Raw: []byte{1}}).StringValue(); !errorsIs(err, ErrInvalidUTF16) {
		t.Fatalf("odd string error=%v", err)
	}
	if _, err := (Value{Type: RegSZ, Raw: []byte{0x00, 0xd8}}).StringValue(); !errorsIs(err, ErrInvalidUTF16) {
		t.Fatalf("surrogate error=%v", err)
	}
	if _, err := (Value{Type: RegMultiSZ, Raw: utf16Bytes("one")}).Strings(); !errorsIs(err, ErrMalformed) {
		t.Fatalf("unterminated multi-string error=%v", err)
	}
}

func TestNegativeOptionRejected(t *testing.T) {
	f := makeFixture()
	if _, err := Open(bytes.NewReader(f.b), int64(len(f.b)), Options{MaxValueBytes: -1}); !errorsIs(err, ErrMalformed) {
		t.Fatalf("negative option error=%v", err)
	}
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestBoundsAndMalformedInputs(t *testing.T) {
	f := makeFixture()
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"short", func(b []byte) { _ = b }},
		{"signature", func(b []byte) { b[0] = 'x' }},
		{"version", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 2) }},
		{"root", func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 0xfffffff8) }},
		{"hbin", func(b []byte) { b[baseBlockSize] = 'x' }},
		{"hbin-size", func(b []byte) { binary.LittleEndian.PutUint32(b[baseBlockSize+8:], 0xffffffff) }},
		{"root-cell", func(b []byte) { binary.LittleEndian.PutUint32(b[baseBlockSize+int(f.root):], 0) }},
		{"index-cycle", func(b []byte) { binary.LittleEndian.PutUint32(b[baseBlockSize+int(f.rootList)+4:], f.rootList) }},
		{"bad-value-offset", func(b []byte) { binary.LittleEndian.PutUint32(b[baseBlockSize+int(f.badValue)+4+8:], 0xfffffff8) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), f.b...)
			if tc.name == "short" {
				b = b[:baseBlockSize-1]
			} else {
				tc.mutate(b)
			}
			defer func() {
				if x := recover(); x != nil {
					t.Fatalf("panic: %v", x)
				}
			}()
			r, err := Open(bytes.NewReader(b), int64(len(b)), Options{})
			if tc.name == "bad-value-offset" || tc.name == "index-cycle" || tc.name == "root-cell" {
				if err != nil {
					return
				}
				if tc.name == "root-cell" {
					_, err = r.OpenKey("")
				} else {
					var k *Key
					k, err = r.OpenKey("Values")
					if err == nil {
						_, err = k.Value("Large")
					}
				}
				if err == nil {
					t.Fatal("expected malformed hive error")
				}
			} else if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLimits(t *testing.T) {
	_, r := openFixture(t)
	k, _ := r.OpenKey("Values")
	if _, err := k.Value("Large"); err != nil {
		t.Fatal(err)
	}
	_, r = openFixture(t)
	k, _ = r.OpenKey("Values")
	r.opts.MaxValueBytes = 100
	if _, err := k.Value("Large"); !errorsIs(err, ErrValueTooLarge) {
		t.Fatalf("limit error=%v", err)
	}
}

func FuzzOpen(f *testing.F) {
	fixture := makeFixture().b
	f.Add(fixture)
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if recover() != nil {
				t.Fatalf("panic")
			}
		}()
		r, err := Open(bytes.NewReader(data), int64(len(data)), Options{})
		if err == nil {
			_, _ = r.OpenKey("ControlSet001\\Control\\Lsa")
		}
	})
}

func FuzzLookupAndValues(f *testing.F) {
	fixture := makeFixture().b
	f.Add(fixture, `ControlSet001\Control\Lsa`, "JD")
	f.Fuzz(func(t *testing.T, data []byte, path, valueName string) {
		defer func() {
			if recover() != nil {
				t.Fatalf("panic")
			}
		}()
		r, err := Open(bytes.NewReader(data), int64(len(data)), Options{})
		if err != nil {
			return
		}
		k, err := r.OpenKey(path)
		if err == nil {
			_, _ = k.Value(valueName)
			_, _ = k.Subkeys()
		}
	})
}

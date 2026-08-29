// Package testfixture contains deterministic, synthetic registry hives for tests.
package testfixture

import (
	"encoding/binary"
	"unicode/utf16"
)

const (
	base = 4096
	bins = 0x10000
)

// Spec controls the small SYSTEM-shaped hive produced by Build.
type Spec struct {
	Current           *uint32
	IncludeSelect     bool
	IncludeCurrent    bool
	CurrentType       uint32
	CurrentRaw        []byte
	IncludeControl    bool
	IncludeControlSet bool
	IncludeControl2   bool
	IncludeLSA        bool
	Fragments         map[string]string
	Fragments2        map[string]string
}

type builder struct {
	b    []byte
	next uint32
}

// Build returns a license-clean synthetic REGF hive. It contains no secrets.
func Build(spec Spec) []byte {
	b := &builder{b: make([]byte, base+bins), next: 0x20}
	copy(b.b[:4], "regf")
	binary.LittleEndian.PutUint32(b.b[20:], 1)
	binary.LittleEndian.PutUint32(b.b[24:], 5)
	copy(b.b[base:base+4], "hbin")
	binary.LittleEndian.PutUint32(b.b[base+8:], bins)
	root := b.nk("ROOT")
	binary.LittleEndian.PutUint16(b.payload(root)[2:], 0x2c)
	children := []uint32{}
	if spec.IncludeSelect || spec.Current != nil || spec.CurrentRaw != nil || spec.CurrentType != 0 {
		selectKey := b.nk("Select")
		if spec.IncludeCurrent || spec.Current != nil || spec.CurrentRaw != nil || spec.CurrentType != 0 {
			currentType := spec.CurrentType
			if currentType == 0 {
				currentType = 4
			}
			raw := spec.CurrentRaw
			if raw == nil && spec.Current != nil {
				raw = make([]byte, 4)
				binary.LittleEndian.PutUint32(raw, *spec.Current)
			}
			value := b.vk("Current", currentType, raw)
			list := b.valueList(value)
			b.setValues(selectKey, 1, list)
		}
		children = append(children, selectKey)
	}
	if spec.IncludeControl || spec.IncludeControlSet {
		children = append(children, b.controlSet("ControlSet001", spec.Fragments, spec.IncludeControl, spec.IncludeLSA))
		if spec.IncludeControl2 {
			children = append(children, b.controlSet("ControlSet002", spec.Fragments2, spec.IncludeControl, spec.IncludeLSA))
		}
	}
	b.setChildren(root, children)
	binary.LittleEndian.PutUint32(b.b[36:], root)
	binary.LittleEndian.PutUint32(b.b[40:], bins)
	var checksum uint32
	for i := 0; i < 508; i += 4 {
		checksum ^= binary.LittleEndian.Uint32(b.b[i:])
	}
	binary.LittleEndian.PutUint32(b.b[508:], checksum)
	return b.b
}

func (b *builder) controlSet(name string, fragments map[string]string, includeControl, includeLSA bool) uint32 {
	cs, control := b.nk(name), b.nk("Control")
	if !includeControl {
		b.setChildren(cs, nil)
		return cs
	}
	controlChildren := []uint32{}
	if includeLSA || len(fragments) > 0 {
		lsa := b.nk("Lsa")
		lsaChildren := []uint32{}
		for _, name := range []string{"JD", "Skew1", "GBG", "Data"} {
			if class, ok := fragments[name]; ok {
				lsaChildren = append(lsaChildren, b.nkClass(name, class))
			}
		}
		b.setChildren(lsa, lsaChildren)
		controlChildren = append(controlChildren, lsa)
	}
	b.setChildren(control, controlChildren)
	b.setChildren(cs, []uint32{control})
	return cs
}

func (b *builder) cell(p []byte) uint32 {
	total := uint32((4 + len(p) + 7) &^ 7)
	rel := b.next
	b.next += total
	binary.LittleEndian.PutUint32(b.b[base+int(rel):], uint32(-int32(total)))
	copy(b.b[base+int(rel)+4:], p)
	return rel
}
func (b *builder) payload(rel uint32) []byte {
	size := -int32(binary.LittleEndian.Uint32(b.b[base+int(rel):]))
	return b.b[base+int(rel)+4 : base+int(rel)+int(size)]
}
func (b *builder) nk(name string) uint32 {
	p := make([]byte, 0x50+len(name))
	copy(p, []byte("nk"))
	binary.LittleEndian.PutUint16(p[2:], 0x20)
	binary.LittleEndian.PutUint16(p[0x48:], uint16(len(name)))
	copy(p[0x4c:], name)
	return b.cell(p)
}
func (b *builder) nkClass(name, class string) uint32 {
	rel := b.nk(name)
	data := []byte{}
	for _, u := range utf16.Encode([]rune(class)) {
		var x [2]byte
		binary.LittleEndian.PutUint16(x[:], u)
		data = append(data, x[:]...)
	}
	c := b.cell(data)
	p := b.payload(rel)
	binary.LittleEndian.PutUint32(p[0x30:], c)
	binary.LittleEndian.PutUint16(p[0x4a:], uint16(len(data)))
	return rel
}
func (b *builder) list(children ...uint32) uint32 {
	p := make([]byte, 4+len(children)*8)
	copy(p, []byte("lf"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(children)))
	for i, child := range children {
		binary.LittleEndian.PutUint32(p[4+i*8:], child)
		childPayload := b.payload(child)
		nameLength := int(binary.LittleEndian.Uint16(childPayload[0x48:]))
		if nameLength > 4 {
			nameLength = 4
		}
		copy(p[4+i*8+4:4+i*8+4+nameLength], childPayload[0x4c:0x4c+nameLength])
	}
	return b.cell(p)
}

func (b *builder) valueList(values ...uint32) uint32 {
	p := make([]byte, len(values)*4)
	for i, value := range values {
		binary.LittleEndian.PutUint32(p[i*4:], value)
	}
	return b.cell(p)
}
func (b *builder) setChildren(key uint32, children []uint32) {
	p := b.payload(key)
	binary.LittleEndian.PutUint32(p[20:], uint32(len(children)))
	if len(children) > 0 {
		binary.LittleEndian.PutUint32(p[28:], b.list(children...))
	}
}
func (b *builder) setValues(key, count uint32, list uint32) {
	p := b.payload(key)
	binary.LittleEndian.PutUint32(p[36:], count)
	binary.LittleEndian.PutUint32(p[40:], list)
}
func (b *builder) vk(name string, typ uint32, raw []byte) uint32 {
	p := make([]byte, 0x14+len(name))
	copy(p, []byte("vk"))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(name)))
	if len(raw) <= 4 {
		binary.LittleEndian.PutUint32(p[4:], 0x80000000|uint32(len(raw)))
		var inline [4]byte
		copy(inline[:], raw)
		copy(p[8:], inline[:])
	} else {
		binary.LittleEndian.PutUint32(p[4:], uint32(len(raw)))
		binary.LittleEndian.PutUint32(p[8:], b.cell(raw))
	}
	binary.LittleEndian.PutUint32(p[12:], typ)
	if name != "" {
		binary.LittleEndian.PutUint16(p[16:], 1)
	}
	copy(p[0x14:], name)
	return b.cell(p)
}

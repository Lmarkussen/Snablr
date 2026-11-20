package msrpc

import (
	"encoding/binary"
	"reflect"
	"testing"
	"unicode/utf16"
)

func ndrString(value string) []byte {
	chars := utf16.Encode([]rune(value + "\x00"))
	b := make([]byte, 12, 12+len(chars)*2+2)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(chars)))
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(chars)))
	for _, ch := range chars {
		b = binary.LittleEndian.AppendUint16(b, ch)
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

type share2 struct {
	name, remark, path string
	nullRemark         bool
}

// level2Response builds a NetShareEnumAll level 2 response the way Windows
// encodes it: fixed SHARE_INFO_2 entries, then each entry's strings.
func level2Response(shares []share2) []byte {
	le := binary.LittleEndian
	b := make([]byte, 48)
	b[0], b[1], b[2] = RPC_VERSION, RPC_VERSION_MINOR, RPC_TYPE_RESPONSE
	le.PutUint32(b[24:28], 2)
	le.PutUint32(b[28:32], 2)
	le.PutUint32(b[32:36], 0x20000)
	le.PutUint32(b[36:40], uint32(len(shares)))
	le.PutUint32(b[40:44], 0x20004)
	le.PutUint32(b[44:48], uint32(len(shares)))
	ref := uint32(0x20008)
	var strings []byte
	for _, s := range shares {
		fixed := make([]byte, 32)
		le.PutUint32(fixed[0:4], ref)
		ref += 4
		strings = append(strings, ndrString(s.name)...)
		if !s.nullRemark {
			le.PutUint32(fixed[8:12], ref)
			ref += 4
			strings = append(strings, ndrString(s.remark)...)
		}
		le.PutUint32(fixed[24:28], ref)
		ref += 4
		strings = append(strings, ndrString(s.path)...)
		b = append(b, fixed...)
	}
	b = append(b, strings...)
	return append(b, make([]byte, 12)...) // total entries, resume handle, status
}

func TestShareInfo2ListDecodesNamesAndPaths(t *testing.T) {
	resp := NetShareEnumAllResponseDecoder(level2Response([]share2{
		{name: "C$", remark: "Default share", path: `C:\`},
		{name: "software_dist", path: `C:\software_dist`, nullRemark: true},
		{name: "IPC$", remark: "Remote IPC", path: ""},
	}))
	got, ok := resp.ShareInfo2List()
	want := []ShareInfo2{{Name: "C$", Path: `C:\`}, {Name: "software_dist", Path: `C:\software_dist`}, {Name: "IPC$", Path: ""}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("shares=%+v ok=%v", got, ok)
	}
	if resp.IsIncomplete() {
		t.Fatal("complete response reported incomplete")
	}
	if _, ok := NetShareEnumAllResponseDecoder(resp[:len(resp)-40]).ShareInfo2List(); ok {
		t.Fatal("truncated response decoded")
	}
	if !NetShareEnumAllResponseDecoder(resp[:len(resp)-40]).IsIncomplete() {
		t.Fatal("truncated response not reported incomplete")
	}
	denied := NetShareEnumAllResponseDecoder(level2Response(nil))
	if shares, ok := denied.ShareInfo2List(); !ok || len(shares) != 0 {
		t.Fatalf("denied response: shares=%v ok=%v", shares, ok)
	}
}

package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/hirochachacha/go-smb2/internal/erref"
)

// errorResponse builds an SMB2 ERROR response body carrying the given error
// contexts; every context but the last is padded to 8 bytes, as Windows
// sends them.
func errorResponse(contexts ...[]byte) []byte {
	var data []byte
	for i, ctx := range contexts {
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header[:4], uint32(len(ctx)))
		data = append(data, header...)
		data = append(data, ctx...)
		if i < len(contexts)-1 {
			for len(data)%8 != 0 {
				data = append(data, 0)
			}
		}
	}
	res := make([]byte, 8, 8+len(data))
	binary.LittleEndian.PutUint16(res[:2], 9)
	res[2] = byte(len(contexts))
	binary.LittleEndian.PutUint32(res[4:8], uint32(len(data)))
	return append(res, data...)
}

// A directory junction answers an open with STATUS_STOPPED_ON_SYMLINK and one
// symbolic-link error context whose length is not a multiple of 8.
func TestAcceptErrorWithUnpaddedLastContext(t *testing.T) {
	link := bytes.Repeat([]byte{0x5c}, 13)
	err := acceptError(uint32(STATUS_STOPPED_ON_SYMLINK), errorResponse(link))
	rerr, ok := err.(*ResponseError)
	if !ok {
		t.Fatalf("error=%v (%T), want a response error", err, err)
	}
	if NtStatus(rerr.Code) != STATUS_STOPPED_ON_SYMLINK || len(rerr.data) != 1 || !bytes.Equal(rerr.data[0], link) {
		t.Fatalf("response error=%+v", rerr)
	}

	first, second := []byte{1, 2, 3}, []byte{4, 5, 6, 7, 8}
	err = acceptError(uint32(STATUS_STOPPED_ON_SYMLINK), errorResponse(first, second))
	rerr, ok = err.(*ResponseError)
	if !ok || len(rerr.data) != 2 || !bytes.Equal(rerr.data[0], first) || !bytes.Equal(rerr.data[1], second) {
		t.Fatalf("two contexts: error=%v", err)
	}
}

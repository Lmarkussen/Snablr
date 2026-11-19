package smb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/hirochachacha/go-smb2"
)

type countingReader struct {
	data  []byte
	reads int
}

func (r *countingReader) Read(b []byte) (int, error) {
	r.reads++
	if len(r.data) == 0 {
		return 0, errors.New("synthetic request after the known end of file")
	}
	n := copy(b, r.data)
	r.data = r.data[n:]
	return n, nil
}

// A file whose size is known from the open response is read with exactly the
// requests needed for its bytes, without a further request that only returns
// end-of-file.
func TestKnownSizeReaderStopsAtOpenedSize(t *testing.T) {
	source := &countingReader{data: []byte("synthetic content")}
	data, err := readFileContent(knownSizeReader(source, int64(len(source.data))), 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "synthetic content" || source.reads != 1 {
		t.Fatalf("data=%q reads=%d, want full content in one read", data, source.reads)
	}
}

// A reported size of zero is not trusted: the file is read to end-of-file.
func TestKnownSizeReaderReadsZeroSizeToEnd(t *testing.T) {
	source := &countingReader{data: []byte("late content")}
	data, err := readFileContent(knownSizeReader(source, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "late content" {
		t.Fatalf("data=%q, want content of a file reported as empty", data)
	}
}

func TestReadShareUnusableClassifiesErrors(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		unusable bool
		ended    bool
	}{
		{"file not found", &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: 0xC0000034}}, false, false},
		{"access denied", &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: 0xC0000022}}, false, false},
		{"read permission", fmt.Errorf("read x on s: %w", os.ErrPermission), false, false},
		{"too large", fmt.Errorf("%w: x", ErrFileTooLarge), false, false},
		{"directory", fmt.Errorf("x on s %w", errIsDirectory), false, false},
		{"tree ended", fmt.Errorf("open x on s: %w", &os.PathError{Op: "open", Path: "x", Err: &smb2.ResponseError{Code: statusNetworkNameDeleted}}), true, true},
		{"timeout", fmt.Errorf("open x on s: %w", ErrOperationTimeout), true, false},
		{"unresponsive", ErrHostUnresponsive, true, false},
		{"cancelled", fmt.Errorf("open x on s: %w", context.Canceled), true, false},
	}
	for _, tc := range cases {
		if got := readShareUnusable(tc.err); got != tc.unusable {
			t.Errorf("%s: unusable=%v, want %v", tc.name, got, tc.unusable)
		}
		if got := treeConnectionEnded(tc.err); got != tc.ended {
			t.Errorf("%s: ended=%v, want %v", tc.name, got, tc.ended)
		}
	}
}

func TestForgetReadShareOnlyDropsSameConnection(t *testing.T) {
	c := NewClient()
	current, stale := &smb2.Share{}, &smb2.Share{}
	c.readShares = map[string]*smb2.Share{"SyntheticShare": current}
	c.forgetReadShare("SyntheticShare", stale)
	if c.readShares["SyntheticShare"] != current {
		t.Fatal("forgetting a stale connection dropped the current one")
	}
	c.forgetReadShare("SyntheticShare", current)
	if _, ok := c.readShares["SyntheticShare"]; ok {
		t.Fatal("connection was not forgotten")
	}
	c.readShares = map[string]*smb2.Share{"SyntheticShare": current}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.readShares != nil {
		t.Fatal("closing the session kept reused read connections")
	}
}

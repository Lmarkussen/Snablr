package smb

import (
	"errors"
	"io"
	"testing"
)

// statusAfterDataReader emulates an SMB read that delivers the file's bytes and
// then, on the following read, returns a non-EOF status. Real servers do this
// at end-of-file, and the delivered bytes must not be discarded.
type statusAfterDataReader struct {
	data []byte
	done bool
}

func (r *statusAfterDataReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("unexpected status: invalid response error")
}

func TestReadFileContentKeepsBytesDeliveredBeforeStatus(t *testing.T) {
	t.Parallel()
	content := []byte("AdminPassword=Synthetic-Read-123!\n")
	got, err := readFileContent(&statusAfterDataReader{data: content}, 0)
	if err != nil {
		t.Fatalf("readFileContent returned error despite delivered bytes: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("readFileContent = %q, want %q", got, content)
	}
}

func TestReadFileContentReportsStatusWithoutData(t *testing.T) {
	t.Parallel()
	_, err := readFileContent(errorReader{}, 0)
	if err == nil {
		t.Fatal("readFileContent must surface a status when no data was delivered")
	}
}

func TestReadFileContentStopsAtEOF(t *testing.T) {
	t.Parallel()
	got, err := readFileContent(&statusAfterDataReader{data: []byte("x")}, 0)
	if err != nil || string(got) != "x" {
		t.Fatalf("readFileContent = %q, %v", got, err)
	}
	if _, err := readFileContent(io.LimitReader(errorReader{}, 0), 0); err != nil {
		t.Fatalf("empty reader returned error: %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

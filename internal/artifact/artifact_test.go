package artifact

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTempFileSupportsSequentialAndRandomAccess(t *testing.T) {
	dir := t.TempDir()
	f, err := NewTempFile(dir, KindSAM, Origin{Host: "host", Share: "share"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteFrom(context.Background(), strings.NewReader("abcdef"), 32); err != nil {
		t.Fatal(err)
	}
	r, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(b) != "abcdef" {
		t.Fatalf("read=%q err=%v", b, err)
	}
	ra, closer, err := f.OpenAt()
	if err != nil {
		t.Fatal(err)
	}
	b = make([]byte, 3)
	if _, err := ra.ReadAt(b, 2); err != nil {
		t.Fatal(err)
	}
	_ = closer.Close()
	if string(b) != "cde" {
		t.Fatalf("random read=%q", b)
	}
	if f.Size() != 6 {
		t.Fatalf("size=%d", f.Size())
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.Base(f.path))); !os.IsNotExist(err) {
		t.Fatalf("artifact remains: %v", err)
	}
}

func TestTempFileRejectsOversizeAndCleans(t *testing.T) {
	f, err := NewTempFile(t.TempDir(), KindNTDS, Origin{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteFrom(context.Background(), strings.NewReader("12345"), 4); err != ErrTooLarge {
		t.Fatalf("err=%v", err)
	}
	if f.Size() != 0 {
		t.Fatalf("size=%d", f.Size())
	}
}

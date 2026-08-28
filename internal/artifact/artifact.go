package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

type Kind string

const (
	KindSAM      Kind = "sam"
	KindSYSTEM   Kind = "system"
	KindSECURITY Kind = "security"
	KindNTDS     Kind = "ntds"
)

type Origin struct {
	Host          string
	Share         string
	ContainerPath string
	MemberPath    string
	ContainerType string
	ImageIndex    int
}

// KindForPath classifies exact Windows secret-artifact filenames. It does not
// infer artifact types from parent directories or extensions such as .bak.
func KindForPath(value string) (Kind, bool) {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	switch strings.ToLower(path.Base(value)) {
	case "sam":
		return KindSAM, true
	case "system":
		return KindSYSTEM, true
	case "security":
		return KindSECURITY, true
	case "ntds.dit":
		return KindNTDS, true
	default:
		return "", false
	}
}

type Binary interface {
	Kind() Kind
	Origin() Origin
	Size() int64
	Open() (io.ReadCloser, error)
	OpenAt() (io.ReaderAt, io.Closer, error)
	Close() error
}

var ErrTooLarge = errors.New("artifact exceeds its size limit")

type TempFile struct {
	mu     sync.Mutex
	path   string
	kind   Kind
	origin Origin
	size   int64
	closed bool
}

func NewTempFile(dir string, kind Kind, origin Origin) (*TempFile, error) {
	if dir == "" {
		return nil, fmt.Errorf("artifact temp directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact workspace: %w", err)
	}
	f, err := os.CreateTemp(dir, "artifact-")
	if err != nil {
		return nil, fmt.Errorf("create artifact file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("restrict artifact file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("close artifact file: %w", err)
	}
	return &TempFile{path: filepath.Clean(f.Name()), kind: kind, origin: origin}, nil
}

func (f *TempFile) Kind() Kind { return f.kind }

func (f *TempFile) Origin() Origin { return f.origin }

func (f *TempFile) Size() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size
}

func (f *TempFile) SetSize(size int64) {
	f.mu.Lock()
	f.size = size
	f.mu.Unlock()
}

func (f *TempFile) WriteFrom(ctx context.Context, src io.Reader, maxBytes int64) (int64, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, os.ErrClosed
	}
	name := f.path
	f.mu.Unlock()

	out, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open artifact file: %w", err)
	}
	defer out.Close()

	reader := io.Reader(src)
	if maxBytes >= 0 && maxBytes < int64(^uint64(0)>>1) {
		reader = io.LimitReader(src, maxBytes+1)
	}
	written, copyErr := copyContext(ctx, out, reader)
	if copyErr != nil {
		return written, copyErr
	}
	if maxBytes >= 0 && written > maxBytes {
		return written, ErrTooLarge
	}
	f.SetSize(written)
	return written, nil
}

func (f *TempFile) OpenWriter(maxBytes int64) (io.WriteCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	out, err := os.OpenFile(f.path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &limitedWriter{file: out, owner: f, max: maxBytes}, nil
}

type limitedWriter struct {
	file         *os.File
	owner        *TempFile
	max, written int64
	tooLarge     bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.max >= 0 && w.written+int64(len(p)) > w.max {
		w.tooLarge = true
		return 0, ErrTooLarge
	}
	n, err := w.file.Write(p)
	w.written += int64(n)
	return n, err
}

func (w *limitedWriter) Close() error {
	err := w.file.Close()
	if err == nil && !w.tooLarge {
		w.owner.SetSize(w.written)
	}
	if err != nil {
		return err
	}
	if w.tooLarge {
		return ErrTooLarge
	}
	return nil
}

func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		n, err := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

func (f *TempFile) Open() (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	return os.Open(f.path)
}

func (f *TempFile) OpenAt() (io.ReaderAt, io.Closer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, nil, os.ErrClosed
	}
	file, err := os.Open(f.path)
	if err != nil {
		return nil, nil, err
	}
	return file, file, nil
}

func (f *TempFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

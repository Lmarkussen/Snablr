package smb

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func (c *Client) ReadFile(share, path string) ([]byte, error) {
	fs, err := c.mountShare(share)
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	info, err := fs.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s on %s: %w", path, share, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s on %s is a directory", path, share)
	}
	if c.maxReadSize > 0 && info.Size() > c.maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s is %d bytes, limit is %d", ErrFileTooLarge, path, share, info.Size(), c.maxReadSize)
	}

	file, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", path, share, err)
	}
	defer file.Close()

	data, err := readFileContent(file, c.maxReadSize)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("read %s on %s: permission denied", path, share)
		}
		return nil, fmt.Errorf("read %s on %s: %w", path, share, err)
	}

	if c.maxReadSize > 0 && int64(len(data)) > c.maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s exceeded the read limit", ErrFileTooLarge, path, share)
	}

	return data, nil
}

// readFileContent reads a remote file to completion. It collects bytes as they
// arrive and only surfaces an error when a read fails before producing any
// data. SMB servers commonly return the last chunk of a file together with a
// non-EOF status on the following read; that status must not discard the
// already-delivered content, or the file is silently lost to content analysis.
func readFileContent(file io.Reader, maxReadSize int64) ([]byte, error) {
	var data []byte
	buffer := make([]byte, 64*1024)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			data = append(data, buffer[:n]...)
			if maxReadSize > 0 && int64(len(data)) > maxReadSize {
				return data, ErrFileTooLarge
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return data, nil
			}
			// A non-EOF status after any content was delivered marks
			// end-of-stream: keep the content. A status before any content is a
			// genuine failure that must be reported.
			if len(data) > 0 {
				return data, nil
			}
			return nil, err
		}
		if n == 0 {
			return data, nil
		}
	}
}

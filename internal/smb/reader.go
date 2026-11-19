package smb

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/hirochachacha/go-smb2"
)

func (c *Client) ReadFile(share, path string) ([]byte, error) {
	maxReadSize := c.readLimit()
	fs, err := c.mountShare(share)
	if err != nil {
		return nil, err
	}
	defer closeShare(fs)

	// One idle watchdog covers stat, open and the read; it restarts whenever
	// data arrives, so slow transfers continue and stalled ones time out.
	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, fmt.Errorf("read %s on %s: %w", path, share, err)
	}
	defer watchdog.stop()
	fs = fs.WithContext(watchdog.ctx)

	info, err := fs.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s on %s: %w", path, share, c.observe(err))
	}
	watchdog.touch()
	if info.IsDir() {
		return nil, fmt.Errorf("%s on %s is a directory", path, share)
	}
	if maxReadSize > 0 && info.Size() > maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s is %d bytes, limit is %d", ErrFileTooLarge, path, share, info.Size(), maxReadSize)
	}

	file, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", path, share, c.observe(err))
	}
	defer file.Close()
	watchdog.touch()

	data, err := readFileContent(progressReader{r: file, w: watchdog}, maxReadSize)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("read %s on %s: permission denied", path, share)
		}
		return nil, fmt.Errorf("read %s on %s: %w", path, share, c.observe(err))
	}
	_ = c.observe(nil)

	if maxReadSize > 0 && int64(len(data)) > maxReadSize {
		return nil, fmt.Errorf("%w: %s on %s exceeded the read limit", ErrFileTooLarge, path, share)
	}

	return data, nil
}

// ReadFilePrefix reads at most limit leading bytes of a remote file. Unlike
// ReadFile it does not reject files larger than the limit: it is used to
// inspect the beginning of oversized text files.
func (c *Client) ReadFilePrefix(share, path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("read prefix of %s on %s: limit must be positive", path, share)
	}
	fs, err := c.mountShare(share)
	if err != nil {
		return nil, err
	}
	defer closeShare(fs)

	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, fmt.Errorf("read %s on %s: %w", path, share, err)
	}
	defer watchdog.stop()

	file, err := fs.WithContext(watchdog.ctx).Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s on %s: %w", path, share, c.observe(err))
	}
	defer file.Close()
	watchdog.touch()

	data, err := readFileContent(progressReader{r: io.LimitReader(file, limit), w: watchdog}, 0)
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf("read %s on %s: permission denied", path, share)
		}
		return nil, fmt.Errorf("read %s on %s: %w", path, share, c.observe(err))
	}
	_ = c.observe(nil)
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
			// genuine failure that must be reported. A cancelled or timed-out
			// read is never end-of-stream: the content would be incomplete.
			var contextErr *smb2.ContextError
			if len(data) > 0 && !errors.As(err, &contextErr) {
				return data, nil
			}
			return nil, err
		}
		if n == 0 {
			return data, nil
		}
	}
}

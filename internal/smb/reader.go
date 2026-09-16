package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

func (c *Client) ReadFile(share, path string) ([]byte, error) {
	var data []byte
	// The whole operation (mount, stat, open, read) is retried from the
	// beginning after a transport recovery, so partial bytes from a broken read
	// are always discarded rather than handed to a parser as a complete file.
	err := c.runOperation(context.Background(), fmt.Sprintf("read %s on %s", path, share), true, func(session transportSession) error {
		tree, err := c.mountTreeWithSession(session, share)
		if err != nil {
			return err
		}
		defer func() { _ = tree.Umount() }()

		c.mu.Lock()
		maxReadSize := c.maxReadSize
		c.mu.Unlock()

		info, err := tree.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s on %s: %w", path, share, err)
		}
		if info.IsDir() {
			return fmt.Errorf("%s on %s is a directory", path, share)
		}
		if maxReadSize > 0 && info.Size() > maxReadSize {
			return fmt.Errorf("%w: %s on %s is %d bytes, limit is %d", ErrFileTooLarge, path, share, info.Size(), maxReadSize)
		}

		file, err := tree.Open(path)
		if err != nil {
			return fmt.Errorf("open %s on %s: %w", path, share, err)
		}
		defer file.Close()

		reader := io.Reader(file)
		if maxReadSize > 0 {
			reader = io.LimitReader(file, maxReadSize+1)
		}
		read, err := io.ReadAll(reader)
		if err != nil && !errors.Is(err, io.EOF) {
			if os.IsPermission(err) {
				return fmt.Errorf("read %s on %s: permission denied", path, share)
			}
			return fmt.Errorf("read %s on %s: %w", path, share, err)
		}
		if maxReadSize > 0 && int64(len(read)) > maxReadSize {
			return fmt.Errorf("%w: %s on %s exceeded the read limit", ErrFileTooLarge, path, share)
		}
		data = read
		return nil
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

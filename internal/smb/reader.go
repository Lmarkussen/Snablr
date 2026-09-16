package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// readChunkSize is the read granularity. Progress is measured per chunk, so a
// slow transfer that keeps delivering data is never abandoned, while a stall
// longer than the read idle timeout is.
const readChunkSize = 512 * 1024

func (c *Client) ReadFile(share, path string) ([]byte, error) {
	return c.ReadFileContext(context.Background(), share, path)
}

// ReadFileContext reads a remote file with bounded network operations. Every
// phase (tree connect, stat, open, each read chunk) is bounded, so a wedged
// server is abandoned instead of holding the worker forever.
func (c *Client) ReadFileContext(ctx context.Context, share, path string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var data []byte
	// The whole operation (mount, stat, open, read) is retried from the
	// beginning after a transport recovery, so partial bytes from a broken read
	// are always discarded rather than handed to a parser as a complete file.
	err := c.runOperation(ctx, fmt.Sprintf("read %s on %s", path, share), true, func(session transportSession) error {
		tree, err := c.mountTreeWithSession(ctx, session, share)
		if err != nil {
			return err
		}
		defer func() { _ = c.bounded(ctx, "tree disconnect", c.operationLimit(), tree.Umount) }()

		c.mu.Lock()
		maxReadSize := c.maxReadSize
		c.mu.Unlock()

		var info fs.FileInfo
		err = c.bounded(ctx, "stat", c.operationLimit(), func() error {
			statInfo, statErr := tree.Stat(path)
			if statErr != nil {
				return statErr
			}
			info = statInfo
			return nil
		})
		if err != nil {
			return fmt.Errorf("stat %s on %s: %w", path, share, err)
		}
		if info.IsDir() {
			return fmt.Errorf("%s on %s is a directory", path, share)
		}
		if maxReadSize > 0 && info.Size() > maxReadSize {
			return fmt.Errorf("%w: %s on %s is %d bytes, limit is %d", ErrFileTooLarge, path, share, info.Size(), maxReadSize)
		}

		var file transportFile
		err = c.bounded(ctx, "open", c.operationLimit(), func() error {
			opened, openErr := tree.Open(path)
			if openErr != nil {
				return openErr
			}
			file = opened
			return nil
		})
		if err != nil {
			return fmt.Errorf("open %s on %s: %w", path, share, err)
		}
		defer func() { _ = file.Close() }()

		read, err := c.readAll(ctx, file, maxReadSize, info.Size())
		if err != nil {
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

// readAll reads the remote file in bounded chunks. Each chunk is bounded by the
// read idle timeout, so a server that stops sending mid-file is abandoned and
// the partial bytes are discarded by the caller's retry.
func (c *Client) readAll(ctx context.Context, file transportFile, maxReadSize, expectedSize int64) ([]byte, error) {
	limit := c.readLimit()
	buffer := make([]byte, readBufferSize(expectedSize))
	var collected []byte
	for {
		var read int
		err := c.bounded(ctx, "read", limit, func() error {
			n, readErr := file.Read(buffer)
			read = n
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if read > 0 {
			collected = append(collected, buffer[:read]...)
			if maxReadSize > 0 && int64(len(collected)) > maxReadSize {
				return nil, fmt.Errorf("%w: read exceeded the configured limit", ErrFileTooLarge)
			}
		}
		if read == 0 {
			return collected, nil
		}
	}
}

// readBufferSize sizes the read buffer to the object so small files do not
// allocate a full chunk buffer on the healthy path.
func readBufferSize(expectedSize int64) int {
	const minimumReadBufferSize = 4 * 1024
	if expectedSize > 0 && expectedSize < int64(readChunkSize) {
		size := int(expectedSize)
		if size < minimumReadBufferSize {
			size = minimumReadBufferSize
		}
		return size
	}
	return readChunkSize
}

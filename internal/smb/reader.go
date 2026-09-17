package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
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
	//
	// readDeadline is fixed at the first attempt so retries share one absolute
	// read budget: a peer cannot extend the total by forcing retries, and no
	// single object can be read for longer than readTotalLimit.
	var readDeadline time.Time
	err := c.runOperation(ctx, fmt.Sprintf("read %s on %s", path, share), share, true, func(session transportSession, deadline time.Time) error {
		if readDeadline.IsZero() {
			readDeadline = time.Now().Add(c.readTotalLimit())
		}
		tree, err := c.mountTreeWithSessionLimit(ctx, session, share, c.limitUntil(deadline))
		if err != nil {
			return err
		}
		defer func() { _ = c.bounded(ctx, "tree disconnect", share, c.limitUntil(deadline), tree.Umount) }()

		c.mu.Lock()
		maxReadSize := c.maxReadSize
		c.mu.Unlock()

		info, err := runPhase(c, ctx, "stat", share, c.limitUntil(deadline), func() (fs.FileInfo, error) {
			return tree.Stat(path)
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

		file, err := runPhase(c, ctx, "open", share, c.limitUntil(deadline), func() (transportFile, error) {
			return tree.Open(path)
		})
		if err != nil {
			return fmt.Errorf("open %s on %s: %w", path, share, err)
		}
		defer func() { _ = file.Close() }()

		read, err := c.readAll(ctx, share, file, maxReadSize, info.Size(), readDeadline)
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
//
// deadline is the absolute end of the whole operation budget. The idle timeout
// alone is not sufficient: a peer that delivers a little data just before the
// idle deadline refreshes it on every chunk, and the read could otherwise stay
// alive indefinitely. The absolute bound is what makes the operation budget
// real.
func (c *Client) readAll(ctx context.Context, share string, file transportFile, maxReadSize, expectedSize int64, deadline time.Time) ([]byte, error) {
	buffer := make([]byte, readBufferSize(expectedSize))
	var collected []byte
	for {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, &operationTimeoutError{Operation: "read total budget", Limit: c.readTotalLimit()}
		}
		limit := c.limitBaseUntil(c.readLimit(), deadline)
		read, err := runPhase(c, ctx, "read", share, limit, func() (int, error) {
			n, readErr := file.Read(buffer)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return n, readErr
			}
			return n, nil
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

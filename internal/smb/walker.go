package smb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"io/fs"
)

type WalkOptions struct {
	IncludePaths []string
	ExcludePaths []string
	MaxDepth     int
}

func (c *Client) WalkShare(share string, fn func(RemoteFile) error) error {
	return c.WalkShareWithOptions(share, WalkOptions{}, fn)
}

func (c *Client) WalkShareWithOptions(share string, opts WalkOptions, fn func(RemoteFile) error) error {
	return c.WalkShareWithOptionsContext(context.Background(), share, opts, fn)
}

// WalkShareWithOptionsContext walks one share with the caller's context. Every
// containment wait, reconnect wait and bounded phase in the walk uses it, so
// Ctrl-C, --max-scan-time and target cancellation release a walker that is
// parked on a withheld share instead of leaving it blocked for the rest of the
// recovery budget.
func (c *Client) WalkShareWithOptionsContext(ctx context.Context, share string, opts WalkOptions, fn func(RemoteFile) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if fn == nil {
		return fmt.Errorf("walk callback cannot be nil")
	}

	tree, err := c.mountShareContext(ctx, share)
	if err != nil {
		return err
	}
	defer func() {
		if tree != nil {
			// Tree disconnect is a network call; bound it so a wedged server
			// cannot hang the target at the end of a walk.
			_ = c.bounded(ctx, "tree disconnect", c.operationLimit(), tree.Umount)
		}
	}()

	// readDir restarts the directory listing after a transport recovery so no
	// entries are silently lost; any entry already reported is de-duplicated by
	// the planner/inventory because batches are keyed by remote path.
	readDir := func(path string) ([]fs.FileInfo, error) {
		var entries []fs.FileInfo
		var lastErr error
		for attempt := 0; attempt < totalOperationAttempts; attempt++ {
			current, err := c.currentSession(ctx)
			if err != nil {
				return nil, err
			}
			if tree == nil {
				tree, err = c.mountTreeWithSession(ctx, current, share)
				if err != nil {
					return nil, err
				}
			}
			var listed []fs.FileInfo
			listErr := c.bounded(ctx, "directory enumeration", c.operationLimit(), func() error {
				listed, err = tree.ReadDir(path)
				return err
			})
			err = listErr
			if err == nil {
				entries = listed
				return entries, nil
			}
			lastErr = err
			if !isRetryableOperation(err) {
				return nil, err
			}
			// A directory enumeration that consumed its whole operation bound is
			// not a transient blip: the transport was already invalidated. Allow
			// one bounded retry, then fail the walk so the target moves on
			// instead of spending the whole recovery budget on one directory.
			if errors.Is(err, ErrOperationTimeout) && attempt >= 1 {
				c.noteHardTimeout(share, "read dir "+path+" on "+share)
				if c.noteTransportFailure(share) {
					c.reportAbandonment(share, true, err)
				}
				if blocked := c.healthBlocked(share); blocked != nil {
					return nil, fmt.Errorf("read dir %s on %s: %w", path, share, blocked)
				}
				c.reportEnumerationFailure(share, path, lastErr, attempt+1)
				return nil, fmt.Errorf("read dir %s on %s: %w", path, share, lastErr)
			}
			c.mu.Lock()
			c.stats.OperationsRetried++
			if IsReconnectable(err) {
				c.stats.TransportFailures++
			}
			c.mu.Unlock()
			// Drop the stale tree and re-establish the transport before
			// restarting this directory.
			if tree != nil {
				_ = c.bounded(ctx, "tree disconnect", c.operationLimit(), tree.Umount)
				tree = nil
			}
			if IsReconnectable(err) {
				c.mu.Lock()
				c.stats.EnumerationFailures++
				handler := c.onEvent
				serverName := c.serverName
				c.mu.Unlock()
				emitTransportEvent(handler, TransportEvent{
					Kind: TransportEventRetrying, Server: serverName, Share: share, Operation: "read dir " + path,
					Attempt: attempt + 1, MaxAttempts: maxReconnectAttempts, Err: err,
				})
				if rerr := c.recover(ctx, current); rerr != nil {
					c.reportEnumerationFailure(share, path, lastErr, attempt+1)
					return nil, fmt.Errorf("read dir %s on %s: %w", path, share, lastErr)
				}
			}
			if err := sleepContext(ctx, reconnectBackoff); err != nil {
				return nil, err
			}
		}
		c.mu.Lock()
		c.stats.RetryExhausted++
		c.mu.Unlock()
		c.reportEnumerationFailure(share, path, lastErr, totalOperationAttempts)
		return nil, fmt.Errorf("read dir %s on %s: %w", path, share, lastErr)
	}

	type walkItem struct {
		path  string
		depth int
	}

	stack := []walkItem{{path: "", depth: 0}}
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = c.maxDepth
	}
	for len(stack) > 0 {
		// Work is withheld from an unwell share, but only temporarily: wait for
		// the bounded probe protocol to restore it or abandon it. Aborting here
		// on a transient problem would silently drop every later file of an
		// otherwise healthy share.
		if err := c.waitShareReady(ctx, share); err != nil {
			return err
		}
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := readDir(item.path)
		if err != nil {
			if isPermissionError(err) || os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("read dir %s on %s: %w", item.path, share, err)
		}

		for _, entry := range entries {
			if err := c.waitShareReady(ctx, share); err != nil {
				return err
			}
			remotePath := joinRemotePath(item.path, entry.Name())
			normalizedPath := normalizeRemotePath(remotePath)

			if entry.IsDir() {
				dirDepth := item.depth + 1
				if !shouldDescendRemoteDir(normalizedPath, dirDepth, opts, maxDepth) {
					continue
				}

				file := RemoteFile{
					Host:       c.serverName,
					Share:      share,
					Path:       normalizedPath,
					Name:       entry.Name(),
					Size:       entry.Size(),
					ModifiedAt: entry.ModTime().UTC(),
					IsDir:      true,
					Extension:  strings.ToLower(filepath.Ext(entry.Name())),
				}
				if err := fn(file); err != nil {
					return err
				}

				stack = append(stack, walkItem{path: remotePath, depth: dirDepth})
				continue
			}

			if !shouldIncludeRemoteFile(normalizedPath, item.depth, opts, maxDepth) {
				continue
			}

			file := RemoteFile{
				Host:       c.serverName,
				Share:      share,
				Path:       normalizedPath,
				Name:       entry.Name(),
				Size:       entry.Size(),
				ModifiedAt: entry.ModTime().UTC(),
				IsDir:      entry.IsDir(),
				Extension:  strings.ToLower(filepath.Ext(entry.Name())),
			}

			if err := fn(file); err != nil {
				return err
			}
		}
	}

	return nil
}

func joinRemotePath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + `\` + name
}

// reportEnumerationFailure records one failed directory enumeration. The
// directory path is preserved so the operator sees which subtree may be
// incomplete rather than a single missing file.
func (c *Client) reportEnumerationFailure(share, dir string, err error, attempts int) {
	if err == nil {
		return
	}
	c.mu.Lock()
	handler := c.onFailure
	serverName := c.serverName
	c.mu.Unlock()
	if handler == nil {
		return
	}
	handler(OperationFailure{
		Operation:          "directory enumeration",
		Share:              share,
		Path:               normalizeRemotePath(dir),
		Server:             serverName,
		Category:           CategoryEnumeration,
		Attempts:           attempts,
		ReconnectAttempted: true,
		Err:                err,
	})
}

func normalizeRemotePath(path string) string {
	path = strings.ReplaceAll(path, `\`, `/`)
	path = strings.TrimPrefix(path, "./")
	return strings.TrimPrefix(path, "/")
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "logon failure")
}

func shouldDescendRemoteDir(path string, depth int, opts WalkOptions, maxDepth int) bool {
	if maxDepth > 0 && depth > maxDepth {
		return false
	}
	for _, blocked := range opts.ExcludePaths {
		if remotePathHasPrefix(path, blocked) {
			return false
		}
	}
	if len(opts.IncludePaths) == 0 {
		return true
	}
	for _, allowed := range opts.IncludePaths {
		if remoteDirOverlapsPrefix(path, allowed) {
			return true
		}
	}
	return false
}

func shouldIncludeRemoteFile(path string, depth int, opts WalkOptions, maxDepth int) bool {
	if maxDepth > 0 && depth > maxDepth {
		return false
	}
	for _, blocked := range opts.ExcludePaths {
		if remotePathHasPrefix(path, blocked) {
			return false
		}
	}
	if len(opts.IncludePaths) == 0 {
		return true
	}
	for _, allowed := range opts.IncludePaths {
		if remotePathHasPrefix(path, allowed) {
			return true
		}
	}
	return false
}

func remoteDirOverlapsPrefix(path, prefix string) bool {
	path = normalizeRemotePath(path)
	prefix = normalizeRemotePath(prefix)
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix ||
		strings.HasPrefix(path, prefix+"/") ||
		strings.HasPrefix(prefix, path+"/")
}

func remotePathHasPrefix(path, prefix string) bool {
	path = normalizeRemotePath(path)
	prefix = normalizeRemotePath(prefix)
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

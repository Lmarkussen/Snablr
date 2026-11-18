package smb

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

type WalkOptions struct {
	IncludePaths []string
	ExcludePaths []string
	MaxDepth     int
	// ShouldDescend is consulted at directory boundaries after the directory
	// callback and again before reading a queued directory. It is intentionally
	// cooperative: active SMB calls are allowed to finish.
	ShouldDescend func(string) bool
	// CurrentDirectory reports the directory immediately before its entries
	// are read, allowing cooperative operator actions to identify the actual
	// traversal scope rather than a selected finding.
	CurrentDirectory func(string)
}

func (c *Client) WalkShare(share string, fn func(RemoteFile) error) error {
	return c.WalkShareWithOptions(share, WalkOptions{}, fn)
}

func (c *Client) WalkShareWithOptions(share string, opts WalkOptions, fn func(RemoteFile) error) error {
	if fn == nil {
		return fmt.Errorf("walk callback cannot be nil")
	}

	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer closeShare(fs)

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
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.path != "" && opts.ShouldDescend != nil && !opts.ShouldDescend(normalizeRemotePath(item.path)) {
			continue
		}
		if opts.CurrentDirectory != nil {
			opts.CurrentDirectory(normalizeRemotePath(item.path))
		}

		entries, err := c.readDir(fs, item.path)
		if err != nil {
			if isPermissionError(err) || os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("read dir %s on %s: %w", item.path, share, err)
		}

		for _, entry := range entries {
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

				if opts.ShouldDescend == nil || opts.ShouldDescend(normalizedPath) {
					stack = append(stack, walkItem{path: remotePath, depth: dirDepth})
				}
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

// closeShare unmounts best-effort within a bounded time, also after the scan
// was cancelled or the host stopped responding.
func closeShare(fs *smb2.Share) {
	if fs != nil {
		ctx, cancel := cleanupContext()
		_ = fs.WithContext(ctx).Umount()
		cancel()
	}
}

// readDirBatchSize is the number of entries read per directory request batch;
// the idle watchdog is restarted after every batch.
const readDirBatchSize = 512

// readDir lists a directory like Share.ReadDir (entries sorted by name) but
// in batches under an idle watchdog, so a huge directory on a slow link keeps
// going while a directory listing that makes no progress times out.
func (c *Client) readDir(fs *smb2.Share, dir string) ([]os.FileInfo, error) {
	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, err
	}
	defer watchdog.stop()
	f, err := fs.WithContext(watchdog.ctx).Open(dir)
	if err != nil {
		return nil, c.observe(err)
	}
	defer f.Close()
	var entries []os.FileInfo
	for {
		batch, err := f.Readdir(readDirBatchSize)
		if len(batch) > 0 {
			entries = append(entries, batch...)
			watchdog.touch()
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, c.observe(err)
		}
	}
	_ = c.observe(nil)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
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

// normalizeRemotePrefixPath normalizes a path or scope prefix for prefix
// comparison. Trailing separators are removed so "--path Reports/" and
// "--path Reports" select the same subtree, matching the planner's
// normalizePlanPath.
func normalizeRemotePrefixPath(path string) string {
	return strings.Trim(normalizeRemotePath(path), "/")
}

func remoteDirOverlapsPrefix(path, prefix string) bool {
	path = normalizeRemotePrefixPath(path)
	prefix = normalizeRemotePrefixPath(prefix)
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix ||
		strings.HasPrefix(path, prefix+"/") ||
		strings.HasPrefix(prefix, path+"/")
}

func remotePathHasPrefix(path, prefix string) bool {
	path = normalizeRemotePrefixPath(path)
	prefix = normalizeRemotePrefixPath(prefix)
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

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
	// SkippedDirectory reports a directory the server refused to list for a
	// reason other than access; the walk goes on without it.
	SkippedDirectory func(path string, err error)
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

	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = c.maxDepth
	}
	list := func(dir string) ([]os.FileInfo, error) { return c.readDir(fs, dir) }
	return c.walkTree(share, opts, maxDepth, list, dirPrefetchInFlight, fn)
}

type walkItem struct {
	path  string
	depth int
}

// walkTree walks the directory tree depth-first in name order. Directories
// next on the stack are listed ahead in parallel (up to prefetch at a time);
// entries are still taken and reported strictly in walk order, so callbacks,
// operator actions and output order are the same as without prefetching. All
// listings started ahead have ended when walkTree returns.
func (c *Client) walkTree(share string, opts WalkOptions, maxDepth int, list func(string) ([]os.FileInfo, error), prefetch int, fn func(RemoteFile) error) error {
	prefetcher := newDirPrefetcher(list, prefetch)
	defer prefetcher.wait()

	stack := []walkItem{{path: "", depth: 0}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.path != "" && opts.ShouldDescend != nil && !opts.ShouldDescend(normalizeRemotePath(item.path)) {
			prefetcher.discard(item.path)
			continue
		}
		if opts.CurrentDirectory != nil {
			opts.CurrentDirectory(normalizeRemotePath(item.path))
		}

		entries, err := prefetcher.take(item.path)
		if err != nil {
			if isPermissionError(err) || os.IsNotExist(err) {
				continue
			}
			// One directory the server refuses does not end the walk of
			// the whole share; a failing connection or host still does.
			if item.path != "" && isServerRefusal(err) {
				if opts.SkippedDirectory != nil {
					opts.SkippedDirectory(normalizeRemotePath(item.path), err)
				}
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

				// Junctions (SYSVOL's domain folder) are resolved by the
				// server and walked like folders. A symbolic link the
				// server will not resolve (Users\All Users) is refused and
				// skipped below; Windows' legacy compatibility junctions
				// deny listing, so they do not loop.
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
		// List the directories the walk reaches next while this one's
		// entries are processed.
		for index := len(stack) - 1; index >= 0; index-- {
			if !prefetcher.start(stack[index].path) {
				break
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

// isServerRefusal reports whether the server answered a request with an
// error status or a reply that cannot be read, as opposed to the request
// failing to complete.
func isServerRefusal(err error) bool {
	var responseErr *smb2.ResponseError
	var invalidErr *smb2.InvalidResponseError
	return errors.As(err, &responseErr) || errors.As(err, &invalidErr)
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
// "--path Reports" select the same subtree, and case is folded because SMB
// paths are case-insensitive ("--path finance" selects "Finance").
func normalizeRemotePrefixPath(path string) string {
	return strings.ToLower(strings.Trim(normalizeRemotePath(path), "/"))
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

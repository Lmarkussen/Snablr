package smb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hirochachacha/go-smb2"
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
	if fn == nil {
		return fmt.Errorf("walk callback cannot be nil")
	}

	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()

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

		entries, err := fs.ReadDir(item.path)
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
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "logon failure")
}

func closeShare(fs *smb2.Share) {
	if fs != nil {
		_ = fs.Umount()
	}
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

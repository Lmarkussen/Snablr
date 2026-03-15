package smb

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (c *Client) WriteFile(share, path string, data []byte) error {
	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()

	normalizedPath := normalizeRemotePath(path)
	dir := filepath.Dir(strings.ReplaceAll(normalizedPath, "/", string(os.PathSeparator)))
	if dir != "." && dir != "" {
		if err := fs.MkdirAll(strings.ReplaceAll(dir, string(os.PathSeparator), `\`), 0o755); err != nil {
			return fmt.Errorf("create directory for %s on %s: %w", normalizedPath, share, err)
		}
	}

	if err := fs.WriteFile(strings.ReplaceAll(normalizedPath, "/", `\`), data, 0o644); err != nil {
		return fmt.Errorf("write %s on %s: %w", normalizedPath, share, err)
	}
	return nil
}

func (c *Client) RemoveAll(share, path string) error {
	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()

	normalizedPath := normalizeRemotePath(path)
	if normalizedPath == "" {
		return fmt.Errorf("remove path cannot be empty")
	}

	if err := fs.RemoveAll(strings.ReplaceAll(normalizedPath, "/", `\`)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s on %s: %w", normalizedPath, share, err)
	}
	return nil
}

func (c *Client) FileContentEquals(share, path string, expected []byte) (bool, error) {
	current, err := c.ReadFile(share, path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		if strings.Contains(strings.ToLower(err.Error()), "not exist") || strings.Contains(strings.ToLower(err.Error()), "cannot find") {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(current, expected), nil
}

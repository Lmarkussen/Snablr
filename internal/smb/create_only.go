package smb

import (
	"fmt"
	"os"
	"strings"
)

// Exists reports whether a remote path exists without opening it for writing.
func (c *Client) Exists(share, path string) (bool, error) {
	fs, err := c.mountShare(share)
	if err != nil {
		return false, err
	}
	defer fs.Umount()
	normalized, err := sanitizeWritableRemotePath(path)
	if err != nil {
		return false, err
	}
	_, err = fs.Stat(strings.ReplaceAll(normalized, "/", `\`))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CreateDirectory creates exactly one directory and fails if it already
// exists. It is intentionally separate from the legacy recursive writer.
func (c *Client) CreateDirectory(share, path string) error {
	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()
	normalized, err := sanitizeWritableRemotePath(path)
	if err != nil {
		return err
	}
	if err := fs.Mkdir(strings.ReplaceAll(normalized, "/", `\`), 0o755); err != nil {
		return fmt.Errorf("create directory %s on %s: %w", normalized, share, err)
	}
	return nil
}

// CreateFileExclusive uses SMB FILE_CREATE through O_CREATE|O_EXCL. The
// server rejects the operation if the target already exists.
func (c *Client) CreateFileExclusive(share, path string, data []byte) error {
	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()
	normalized, err := sanitizeWritableRemotePath(path)
	if err != nil {
		return err
	}
	file, err := fs.OpenFile(strings.ReplaceAll(normalized, "/", `\`), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create file %s on %s: %w", normalized, share, err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write file %s on %s: %w", normalized, share, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close file %s on %s: %w", normalized, share, closeErr)
	}
	return nil
}

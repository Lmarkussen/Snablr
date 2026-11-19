package smb

import (
	"errors"
	"os"

	"github.com/hirochachacha/go-smb2"
)

// statusNetworkNameDeleted is STATUS_NETWORK_NAME_DELETED: the server ended
// the tree connection (share), for example after the share was removed.
const statusNetworkNameDeleted = 0xC00000C9

var errIsDirectory = errors.New("is a directory")

// readShare returns the tree connection used for file reads on share. It is
// connected once per share and session and then reused by every read, instead
// of connecting and disconnecting around each file. Mounts are serialized so
// that concurrent readers share one connection. When the session changed while
// mounting, the share is returned uncached and the caller unmounts it.
func (c *Client) readShare(share string) (*smb2.Share, bool, error) {
	c.mountMu.Lock()
	defer c.mountMu.Unlock()

	c.mu.Lock()
	if fs, ok := c.readShares[share]; ok {
		c.mu.Unlock()
		return fs, true, nil
	}
	session := c.session
	c.mu.Unlock()

	fs, err := c.mountShare(share)
	if err != nil {
		return nil, false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil || c.session != session {
		return fs, false, nil
	}
	if c.readShares == nil {
		c.readShares = make(map[string]*smb2.Share)
	}
	c.readShares[share] = fs
	return fs, true, nil
}

// forgetReadShare stops reusing a tree connection after an error that may
// have left it unusable; the next read connects again. It is not unmounted:
// other readers may still be using it, and logoff ends it on the server.
func (c *Client) forgetReadShare(share string, fs *smb2.Share) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if current, ok := c.readShares[share]; ok && current == fs {
		delete(c.readShares, share)
	}
}

// withReadShare runs read on the reused tree connection for share. A read the
// server rejected because the tree connection ended is retried once on a new
// connection.
func (c *Client) withReadShare(share string, read func(*smb2.Share) ([]byte, error)) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		fs, cached, err := c.readShare(share)
		if err != nil {
			return nil, err
		}
		data, err := read(fs)
		if !cached {
			closeShare(fs)
		}
		if err == nil || !readShareUnusable(err) {
			return data, err
		}
		c.forgetReadShare(share, fs)
		if attempt > 0 || !treeConnectionEnded(err) {
			return data, err
		}
	}
}

// readShareUnusable reports whether an error may have left the tree
// connection unusable. A status the server answered for the file itself (not
// found, access denied, sharing violation, ...) and Snablr's own size and
// directory checks leave it intact; timeouts, transport errors and an ended
// tree connection do not.
func readShareUnusable(err error) bool {
	if errors.Is(err, ErrFileTooLarge) || errors.Is(err, errIsDirectory) || errors.Is(err, os.ErrPermission) {
		return false
	}
	var response *smb2.ResponseError
	if errors.As(err, &response) {
		return treeConnectionEnded(err)
	}
	return true
}

func treeConnectionEnded(err error) bool {
	var response *smb2.ResponseError
	return errors.As(err, &response) && response.Code == statusNetworkNameDeleted
}

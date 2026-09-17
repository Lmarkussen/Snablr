package smb

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

var defaultSkippedShares = []string{"IPC$", "PRINT$"}

func IsAdministrativeShare(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ADMIN$", "C$", "IPC$", "PRINT$":
		return true
	default:
		return false
	}
}

func IsADShare(name string) bool {
	_, ok := ADShareType(name)
	return ok
}

func ADShareType(name string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SYSVOL":
		return "sysvol", true
	case "NETLOGON":
		return "netlogon", true
	default:
		return "", false
	}
}

func (c *Client) ListShares() ([]ShareInfo, error) {
	return c.listShares(context.Background(), false)
}

// ListAccessibleShares returns filesystem shares that the authenticated
// session can tree-connect to and list at the share root. IPC$ and PRINT$ are
// omitted because they are not useful filesystem scan targets. Permission
// failure on one candidate is expected; transport/protocol failures abort.
func (c *Client) ListAccessibleShares(ctx context.Context) ([]ShareInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return c.listShares(ctx, true)
}

func (c *Client) listShares(ctx context.Context, strict bool) ([]ShareInfo, error) {
	session, _, err := c.connectedSession()
	if err != nil {
		return nil, err
	}

	shares, err := session.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}

	return filterAccessibleShareNames(ctx, shares, func(share string) error {
		return c.checkShareAccessContext(ctx, share)
	}, strict)
}

func filterAccessibleShareNames(ctx context.Context, shares []string, check func(string) error, strict bool) ([]ShareInfo, error) {
	if check == nil {
		return nil, fmt.Errorf("share access checker cannot be nil")
	}
	sort.SliceStable(shares, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(shares[i])) < strings.ToLower(strings.TrimSpace(shares[j]))
	})
	accessible := make([]ShareInfo, 0, len(shares))
	seen := make(map[string]struct{}, len(shares))
	for _, share := range shares {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(share))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if share == "" || slices.Contains(defaultSkippedShares, strings.ToUpper(share)) {
			continue
		}

		if err := check(share); err != nil {
			if isPermissionError(err) {
				continue
			}
			if strict {
				return nil, fmt.Errorf("validate share %s: %w", share, err)
			}
			continue
		}

		accessible = append(accessible, ShareInfo{
			Name:        share,
			Description: "",
			Type:        inferShareType(share),
		})
	}

	return accessible, nil
}

func (c *Client) checkShareAccess(share string) error {
	return c.checkShareAccessContext(context.Background(), share)
}

func (c *Client) checkShareAccessContext(ctx context.Context, share string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fs, err := c.mountShare(share)
	if err != nil {
		return err
	}
	defer fs.Umount()

	_, err = fs.ReadDir("")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func inferShareType(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if adType, ok := ADShareType(name); ok {
		return adType
	}
	upper := strings.ToUpper(name)
	switch {
	case upper == "IPC$":
		return "ipc"
	case upper == "PRINT$":
		return "print"
	case strings.HasSuffix(name, "$"):
		return "disk-hidden"
	default:
		return "disk"
	}
}

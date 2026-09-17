package smb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
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
	var shares []string
	if err := c.run(ctx, "list shares", "", false, func(session transportSession, deadline time.Time) error {
		var names []string
		err := c.bounded(ctx, "list shares", c.limitUntil(deadline), func() error {
			listed, listErr := session.ListSharenames()
			if listErr != nil {
				return listErr
			}
			names = listed
			return nil
		})
		if err != nil {
			return err
		}
		shares = names
		return nil
	}); err != nil {
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
	// healthFailures counts candidates that could not be validated because of a
	// transport/session problem rather than an ordinary permission denial. If
	// every candidate fails that way, the target is unreachable or unhealthy and
	// an empty share list must not be reported as a successful, complete scan.
	healthFailures := 0
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
			if isHealthFailure(err) {
				healthFailures++
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

	if len(accessible) == 0 && healthFailures > 0 {
		return nil, fmt.Errorf("no share could be validated: %d candidate(s) failed with transport or session errors", healthFailures)
	}
	return accessible, nil
}

// isHealthFailure reports whether verifying share access failed for a
// transport/session reason rather than an ordinary SMB status. It keeps an
// inaccessible-but-healthy server (every share permission-denied) from being
// mistaken for an unreachable one.
func isHealthFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrShareUnhealthy) || errors.Is(err, ErrTargetUnhealthy) {
		return true
	}
	if IsAuthFailure(err) {
		return false
	}
	if errors.Is(err, ErrOperationTimeout) || errors.Is(err, ErrReconnectTimeout) {
		return true
	}
	return IsReconnectable(err)
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
	defer func() {
		// Tree disconnect is a network call as well: a wedged server must not be
		// able to hold the target open in an unbounded umount.
		_ = c.bounded(ctx, "tree disconnect", c.operationLimit(), fs.Umount)
	}()

	// The share-root listing previously ran outside the watchdog entirely, so a
	// server that accepted the tree connect and then stopped answering could
	// freeze share enumeration forever with no cancellation path.
	err = c.bounded(ctx, "share root enumeration", c.operationLimit(), func() error {
		_, listErr := fs.ReadDir("")
		return listErr
	})
	if errors.Is(err, ErrOperationTimeout) {
		// One wedged root listing is evidence about this share, and any timeout
		// is evidence about the target streak.
		if c.noteHardTimeout(share, "share root enumeration "+share) {
			c.reportAbandonment(share, false, err)
		}
		if c.noteTransportFailure() {
			c.reportAbandonment(share, true, err)
		}
		if blocked := c.healthBlocked(share); blocked != nil {
			return fmt.Errorf("%w: share %s", blocked, share)
		}
	}
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

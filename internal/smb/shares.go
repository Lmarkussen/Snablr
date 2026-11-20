package smb

import (
	"context"
	"errors"
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
	shares, err := c.enumerateShareNames()
	if err != nil {
		return nil, err
	}
	return filterAccessibleShareNames(ctx, shares, func(share string) error {
		return c.checkShareAccessContext(ctx, share)
	}, strict)
}

// ShareListOptions selects the shares ListSharesFiltered tests for access.
type ShareListOptions struct {
	// Allow accepts the shares to test; shares it rejects are never
	// connected to. Nil accepts every share.
	Allow func(string) bool
	// Names, when set, are tested instead of the host's enumerated shares,
	// so the share list is not requested from the host at all.
	Names []string
	// MaxConsecutiveDenied stops testing after this many shares in a row
	// refused access; the shares not tested are returned as rejected.
	// Zero never stops.
	MaxConsecutiveDenied int
}

// ListSharesFiltered tests access only for the shares opts selects and
// returns the accessible ones, plus the names it did not connect to so the
// caller can report them as skipped.
func (c *Client) ListSharesFiltered(opts ShareListOptions) ([]ShareInfo, []string, error) {
	names := opts.Names
	if len(names) == 0 {
		var err error
		if names, err = c.enumerateShareNames(); err != nil {
			return nil, nil, err
		}
	}
	ctx := context.Background()
	return filterAllowedShareNames(ctx, names, opts.Allow, opts.MaxConsecutiveDenied, func(share string) error {
		return c.checkShareAccessContext(ctx, share)
	})
}

// filterAllowedShareNames checks access only for the shares allow accepts
// and returns the accessible ones plus the names it did not check: those
// allow rejected, and those left after maxDenied consecutive denials.
func filterAllowedShareNames(ctx context.Context, names []string, allow func(string) bool, maxDenied int, check func(string) error) ([]ShareInfo, []string, error) {
	allowed, rejected := splitShareNames(names, allow)
	if maxDenied > 0 {
		denied := 0
		inner := check
		check = func(share string) error {
			if denied >= maxDenied {
				return errShareNotChecked
			}
			err := inner(share)
			if err != nil && isPermissionError(err) {
				denied++
			} else if err == nil {
				denied = 0
			}
			return err
		}
	}
	var unchecked []string
	shares, err := filterAccessibleShareNames(ctx, allowed, func(share string) error {
		err := check(share)
		if errors.Is(err, errShareNotChecked) {
			unchecked = append(unchecked, share)
			return os.ErrPermission
		}
		return err
	}, false)
	if err != nil {
		return nil, nil, err
	}
	return shares, append(rejected, unchecked...), nil
}

// errShareNotChecked marks a share left untested after repeated denials.
var errShareNotChecked = errors.New("share not checked after repeated access denials")

func (c *Client) enumerateShareNames() ([]string, error) {
	session, _, err := c.connectedSession()
	if err != nil {
		return nil, err
	}

	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}
	shares, err := session.WithContext(watchdog.ctx).ListSharenames()
	watchdog.stop()
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", c.observe(err))
	}
	_ = c.observe(nil)
	return shares, nil
}

// splitShareNames separates share names into those allow accepts and those
// it rejects, in the order and with the de-duplication and default skips the
// access check applies. A nil allow accepts every share.
func splitShareNames(shares []string, allow func(string) bool) ([]string, []string) {
	sorted := append([]string(nil), shares...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(sorted[i])) < strings.ToLower(strings.TrimSpace(sorted[j]))
	})
	var allowed, rejected []string
	seen := make(map[string]struct{}, len(sorted))
	for _, share := range sorted {
		key := strings.ToLower(strings.TrimSpace(share))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if slices.Contains(defaultSkippedShares, strings.ToUpper(share)) {
			continue
		}
		if allow == nil || allow(share) {
			allowed = append(allowed, share)
		} else {
			rejected = append(rejected, share)
		}
	}
	return allowed, rejected
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
	defer closeShare(fs)

	_, err = c.readDir(fs, "")
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

// SharePaths returns the local path each share exports, keyed by lower-case
// share name. Servers answer this for administrators only; for other
// accounts it returns no paths and no error.
func (c *Client) SharePaths() (map[string]string, error) {
	session, _, err := c.connectedSession()
	if err != nil {
		return nil, err
	}
	watchdog, err := c.operationWatchdog()
	if err != nil {
		return nil, fmt.Errorf("list share paths: %w", err)
	}
	shares, err := session.WithContext(watchdog.ctx).ListSharePaths()
	watchdog.stop()
	if err != nil {
		if isPermissionError(err) {
			_ = c.observe(nil)
			return nil, nil
		}
		return nil, fmt.Errorf("list share paths: %w", c.observe(err))
	}
	_ = c.observe(nil)
	paths := make(map[string]string, len(shares))
	for _, share := range shares {
		name := strings.ToLower(strings.TrimSpace(share.Name))
		if name != "" && strings.TrimSpace(share.Path) != "" {
			paths[name] = strings.TrimSpace(share.Path)
		}
	}
	return paths, nil
}

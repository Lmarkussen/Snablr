package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

type listSharesClient interface {
	ConnectWithAuth(string, smb.Auth) error
	ListAccessibleShares(context.Context) ([]smb.ShareInfo, error)
	Close() error
}

var newListSharesClient = func() listSharesClient { return smb.NewClient() }

type listSharesResult struct {
	targetLabel string
	uncHost     string
	shares      []smb.ShareInfo
}

// runListShares authenticates each reachable target and prints only shares
// that pass tree-connect plus root-list validation. It does not initialize
// rules, scanners, state, checkpoints, or report writers.
func runListShares(ctx context.Context, cfg config.Config, logger *logx.Logger) error {
	if err := runScanPreflightFunc(ctx, cfg, false, logger); err != nil {
		return err
	}
	if logger != nil && !strings.EqualFold(strings.TrimSpace(cfg.App.LogLevel), "debug") {
		logger.SetOutput(io.Discard)
		defer logger.SetOutput(os.Stderr)
	}
	resolved, err := resolveTargetsFunc(ctx, cfg.Scan, logger, nil)
	if err != nil {
		return err
	}
	if len(resolved.ReachableTargets) == 0 {
		return fmt.Errorf("no reachable SMB targets available for --list-shares")
	}

	targets := append([]discovery.Target(nil), resolved.ReachableTargets...)
	sort.SliceStable(targets, func(i, j int) bool {
		return strings.ToLower(listSharesTargetLabel(targets[i])) < strings.ToLower(listSharesTargetLabel(targets[j]))
	})
	identity := listSharesIdentity(cfg.Scan)
	results := make([]listSharesResult, 0, len(targets))
	var errs []error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		host := strings.TrimSpace(target.Hostname)
		if host == "" {
			host = strings.TrimSpace(target.IP)
		}
		client := newListSharesClient()
		auth, err := smbAuthForHost(host, cfg.Scan)
		if err != nil {
			_ = client.Close()
			errs = append(errs, fmt.Errorf("%s: prepare authentication: %w", host, err))
			continue
		}
		if err := client.ConnectWithAuth(host, auth); err != nil {
			_ = client.Close()
			errs = append(errs, fmt.Errorf("%s: connect failed: %w", host, err))
			continue
		}
		shares, err := client.ListAccessibleShares(ctx)
		closeErr := client.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: list accessible shares failed: %w", host, err))
			continue
		}
		if closeErr != nil {
			errs = append(errs, fmt.Errorf("%s: close SMB session: %w", host, closeErr))
			continue
		}
		results = append(results, listSharesResult{
			targetLabel: listSharesTargetLabel(target),
			uncHost:     listSharesUNCHost(target),
			shares:      shares,
		})
	}
	if err := writeListSharesOutput(os.Stdout, identity, results); err != nil {
		return err
	}
	return errors.Join(errs...)
}

func listSharesIdentity(cfg config.ScanConfig) string {
	username := strings.TrimSpace(cfg.Username)
	if username == "" || strings.ContainsAny(username, `\@`) {
		return username
	}
	if domain := strings.TrimSpace(cfg.Domain); domain != "" {
		return domain + `\` + username
	}
	return username
}

func listSharesTargetLabel(target discovery.Target) string {
	host := listSharesUNCHost(target)
	if target.IP != "" && host != target.IP && net.ParseIP(host) == nil {
		return host + " (" + target.IP + ")"
	}
	return host
}

func listSharesUNCHost(target discovery.Target) string {
	host := strings.TrimSpace(target.Hostname)
	if host == "" {
		host = strings.TrimSpace(target.IP)
	}
	if host == "" {
		host = strings.TrimSpace(target.Input)
	}
	return host
}

func writeListSharesOutput(w io.Writer, identity string, results []listSharesResult) error {
	for index, result := range results {
		if index > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		subject := "the authenticated identity"
		if identity != "" {
			subject = identity
		}
		if _, err := fmt.Fprintf(w, "%s\n\n", listSharesColor(w, "36", "Readable shares for "+subject+" on "+result.targetLabel+":")); err != nil {
			return err
		}
		if len(result.shares) == 0 {
			if _, err := fmt.Fprintf(w, "  %s\n\n", listSharesColor(w, "33", "None.")); err != nil {
				return err
			}
		} else {
			for _, share := range result.shares {
				path := `\\` + result.uncHost + `\` + share.Name
				if _, err := fmt.Fprintln(w, listSharesColor(w, "32", "  "+path)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		count := fmt.Sprintf("%d readable share%s found.", len(result.shares), pluralSuffix(len(result.shares)))
		if _, err := fmt.Fprintln(w, listSharesColor(w, "32", count)); err != nil {
			return err
		}
	}
	return nil
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func listSharesColor(w io.Writer, code, value string) string {
	file, ok := w.(*os.File)
	if !ok {
		return value
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 || strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return value
	}
	return "\033[" + code + "m" + value + "\033[0m"
}

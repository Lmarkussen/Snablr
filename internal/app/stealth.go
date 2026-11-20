package app

import (
	"context"
	"math/rand/v2"
	"strings"
	"time"

	"snablr/internal/config"
	"snablr/internal/smb"
	"snablr/pkg/logx"
)

// pacedClient is a scan client whose SMB operations can be paced.
type pacedClient interface {
	SetPacing(smb.Pacing)
}

// applyFilePacing spaces the client's share connections, directory
// listings and file opens by the configured file delay.
func applyFilePacing(client scanClient, cfg config.ScanConfig) {
	min, max, err := config.ParseDelayRange(cfg.FileDelay)
	if err != nil || max <= 0 {
		return
	}
	if paced, ok := client.(pacedClient); ok {
		paced.SetPacing(smb.Pacing{Min: min, Max: max})
	}
}

// pauseBetweenHosts waits a random host delay. It returns early when the
// scan is interrupted.
func pauseBetweenHosts(ctx context.Context, cfg config.ScanConfig, sleep func(context.Context, time.Duration) error) error {
	min, max, err := config.ParseDelayRange(cfg.HostDelay)
	if err != nil || max <= 0 {
		return nil
	}
	delay := min
	if max > min {
		delay += rand.N(max - min + 1)
	}
	return sleep(ctx, delay)
}

// logStealthSummary reports the stealth settings in effect and what still
// leaves a trace, so the operator can adjust before the first host.
func logStealthSummary(cfg config.Config, logger *logx.Logger) {
	if logger == nil || !cfg.Scan.Stealth {
		return
	}
	scan := cfg.Scan
	logger.Infof("stealth: ADMIN$ and drive shares (C$, D$, ...) are not touched unless named with --share")
	logger.Infof("stealth: %d worker(s), file delay %s, host delay %s, max file size %d bytes, WIM inspection %v",
		scan.WorkerCount, valueOr(scan.FileDelay, "none"), valueOr(scan.HostDelay, "none"), scan.MaxFileSize, cfg.WIM.Enabled)
	if scan.StealthMaxDeniedShares > 0 {
		logger.Infof("stealth: a host is left after %d shares in a row refuse access", scan.StealthMaxDeniedShares)
	}
	if scan.StealthReadSensitive {
		logger.Warnf("stealth: hives, ntds.dit, dumps, tickets and mailbox files WILL be opened (--stealth-read-sensitive)")
	} else {
		logger.Infof("stealth: hives, ntds.dit, dumps, tickets and mailbox files are reported by name only")
	}
	if len(scan.Share) > 0 {
		logger.Infof("stealth: named shares are connected to directly; host share lists are not requested")
	}
	smbAuth := strings.ToLower(strings.TrimSpace(scan.SMBAuth))
	if smbAuth != string(smb.AuthModeKerberos) {
		logger.Warnf("stealth: SMB uses NTLM; Kerberos (--smb-auth kerberos) blends in better with domain traffic")
		if strings.TrimSpace(scan.Workstation) == "" {
			logger.Warnf("stealth: no --workstation set; NTLM logons will carry an empty workstation name")
		}
	}
	if len(scan.Targets) == 0 && strings.TrimSpace(scan.TargetsFile) == "" && !scan.NoLDAP {
		logger.Warnf("stealth: no targets given; computers are discovered through LDAP")
	}
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/pkg/logx"
)

const preflightDelay = 3 * time.Second

type preflightValidator interface {
	Name() string
	Validate(context.Context) error
}

type smbPreflightError struct {
	host string
	err  error
}

func (e *smbPreflightError) Error() string {
	return fmt.Sprintf("%s: SMB preflight failed: %v", e.host, e.err)
}

func (e *smbPreflightError) Unwrap() error { return e.err }

type preflightFailureKind string

const (
	preflightInvalidCredentials  preflightFailureKind = "invalid_credentials"
	preflightTargetUnreachable   preflightFailureKind = "target_unreachable"
	preflightSecurityRequirement preflightFailureKind = "security_requirement"
	preflightProtocolError       preflightFailureKind = "protocol_error"
	preflightUnknownError        preflightFailureKind = "preflight_error"
)

type preflightFailure struct {
	kind   preflightFailureKind
	detail string
	err    error
}

func (e *preflightFailure) Error() string { return e.detail }
func (e *preflightFailure) Unwrap() error { return e.err }

type ldapPreflightValidator struct {
	opts   discovery.LDAPOptions
	logger *logx.Logger
}

type smbPreflightValidator struct {
	host   string
	config config.ScanConfig
}

func (v smbPreflightValidator) Name() string { return "credentials" }

func (v smbPreflightValidator) Validate(ctx context.Context) error {
	client := newScanClientFunc()
	defer client.Close()
	auth, err := smbAuthForHost(v.host, v.config)
	if err != nil {
		return err
	}
	if err := client.ConnectWithAuth(v.host, auth); err != nil {
		return &smbPreflightError{host: v.host, err: err}
	}
	return ctx.Err()
}

func (v ldapPreflightValidator) Name() string {
	return "credentials"
}

func (v ldapPreflightValidator) Validate(ctx context.Context) error {
	return discovery.ValidateLDAPCredentials(ctx, v.opts, v.logger)
}

type preflightHooks struct {
	out        io.Writer
	sleep      func(context.Context, time.Duration) error
	validators func(config.Config, *logx.Logger) []preflightValidator
}

func runScanPreflight(ctx context.Context, cfg config.Config, useInteractiveTUI bool, logger *logx.Logger) error {
	return runScanPreflightWithHooks(ctx, cfg, useInteractiveTUI, logger, preflightHooks{
		out:        os.Stdout,
		sleep:      sleepWithContext,
		validators: scanPreflightValidators,
	})
}

func runScanPreflightWithHooks(ctx context.Context, cfg config.Config, useInteractiveTUI bool, logger *logx.Logger, hooks preflightHooks) error {
	if hooks.out == nil {
		hooks.out = io.Discard
	}
	if hooks.sleep == nil {
		hooks.sleep = sleepWithContext
	}
	if hooks.validators == nil {
		hooks.validators = scanPreflightValidators
	}

	validators := hooks.validators(cfg, logger)
	if len(validators) == 0 {
		return nil
	}

	writePreflightLine(hooks.out, colorizePreflight("Checking credentials ...", "33", cfg.Output.NoColor))
	for _, validator := range validators {
		if err := validator.Validate(ctx); err != nil {
			failure := classifyPreflightFailure(err)
			writePreflightLine(hooks.out, colorizePreflight(preflightStatus(failure.kind), preflightStatusColor(failure.kind), cfg.Output.NoColor))
			return failure
		}
	}
	writePreflightLine(hooks.out, colorizePreflight("Credentials are Valid", "32", cfg.Output.NoColor))

	if !useInteractiveTUI {
		return nil
	}
	return hooks.sleep(ctx, preflightDelay)
}

func classifyPreflightFailure(err error) *preflightFailure {
	if err == nil {
		return nil
	}

	kind := preflightUnknownError
	if isTargetUnreachable(err) {
		kind = preflightTargetUnreachable
	} else if isSecurityRequirement(err) {
		kind = preflightSecurityRequirement
	} else if isAuthenticationRejection(err) {
		kind = preflightInvalidCredentials
	} else if isProtocolFailure(err) {
		kind = preflightProtocolError
	}

	detail := concisePreflightDetail(err, kind)
	return &preflightFailure{kind: kind, detail: detail, err: err}
}

func preflightStatus(kind preflightFailureKind) string {
	switch kind {
	case preflightInvalidCredentials:
		return "Credentials Invalid"
	case preflightTargetUnreachable:
		return "Target Unreachable"
	case preflightSecurityRequirement, preflightProtocolError, preflightUnknownError:
		return "Preflight Error"
	default:
		return "Preflight Error"
	}
}

func preflightStatusColor(kind preflightFailureKind) string {
	if kind == preflightTargetUnreachable {
		return "33"
	}
	return "31"
}

func concisePreflightDetail(err error, kind preflightFailureKind) string {
	var smbErr *smbPreflightError
	if errors.As(err, &smbErr) {
		switch kind {
		case preflightTargetUnreachable:
			if isTimeout(err) {
				return fmt.Sprintf("%s: SMB connection timed out", smbErr.host)
			}
			return fmt.Sprintf("%s: SMB service is not reachable on port 445", smbErr.host)
		case preflightInvalidCredentials:
			return fmt.Sprintf("%s: SMB credentials were rejected", smbErr.host)
		case preflightSecurityRequirement:
			return fmt.Sprintf("%s: SMB security requirements were not met", smbErr.host)
		case preflightProtocolError:
			return fmt.Sprintf("%s: SMB protocol negotiation failed", smbErr.host)
		default:
			return fmt.Sprintf("%s: SMB preflight failed", smbErr.host)
		}
	}

	switch kind {
	case preflightTargetUnreachable:
		return "Target or directory service is not reachable"
	case preflightSecurityRequirement:
		return "LDAP requires stronger authentication or signing"
	case preflightProtocolError:
		return "SMB/LDAP protocol negotiation failed"
	default:
		return err.Error()
	}
}

func isTargetUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if isTimeout(err) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, hint := range []string{
		"i/o timeout",
		"connection refused",
		"no route to host",
		"network is unreachable",
		"host is unreachable",
	} {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) || os.IsTimeout(err) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

func isSecurityRequirement(err error) bool {
	message := strings.ToLower(err.Error())
	for _, hint := range []string{
		"strongerauthrequired",
		"strong auth required",
		"stronger authentication required",
		"confidentiality required",
		"integrity checking",
		"integrity required",
		"ldap signing required",
		"requires signing",
	} {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

func isAuthenticationRejection(err error) bool {
	message := strings.ToLower(err.Error())
	for _, hint := range []string{
		"status_logon_failure",
		"status_wrong_password",
		"status_account_restriction",
		"status_invalid_logon_hours",
		"status_invalid_workstation",
		"status_password_expired",
		"status_account_disabled",
		"invalid credentials",
		"invalid username or password",
		"ldap result code 49",
		"data 52e",
		"logon failure",
	} {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

func isProtocolFailure(err error) bool {
	message := strings.ToLower(err.Error())
	for _, hint := range []string{
		"negotiate",
		"negotiation",
		"protocol",
		"invalid response",
		"malformed",
		"unsupported smb",
	} {
		if strings.Contains(message, hint) {
			return true
		}
	}
	return false
}

func scanPreflightValidators(cfg config.Config, logger *logx.Logger) []preflightValidator {
	validators := make([]preflightValidator, 0, 1)
	if requiresLDAPPreflight(cfg.Scan) {
		validators = append(validators, ldapPreflightValidator{
			opts: discovery.LDAPOptions{
				Username:         cfg.Scan.Username,
				Password:         cfg.Scan.Password,
				AuthMode:         cfg.Scan.AuthMode,
				KerberosCCache:   cfg.Scan.KerberosCCache,
				LDAPSPN:          cfg.Scan.LDAPSPN,
				Domain:           cfg.Scan.Domain,
				DomainController: cfg.Scan.DomainController,
				BaseDN:           cfg.Scan.BaseDN,
				Timeout:          cfg.Scan.ReachabilityTimeout(),
			},
			logger: logger,
		})
	}
	if len(cfg.Scan.Targets) > 0 {
		host := strings.TrimSpace(cfg.Scan.Targets[0])
		if host != "" {
			validators = append(validators, smbPreflightValidator{host: host, config: cfg.Scan})
		}
	}
	return validators
}

func requiresLDAPPreflight(scanCfg config.ScanConfig) bool {
	hasExplicitTargets := len(scanCfg.Targets) > 0 || strings.TrimSpace(scanCfg.TargetsFile) != ""
	return (!scanCfg.NoLDAP && !hasExplicitTargets) || scanCfg.DiscoverDFS
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writePreflightLine(w io.Writer, line string) {
	_, _ = fmt.Fprintln(w, line)
}

func colorGreen(value string) string {
	return colorizeTerminalString(value, "32")
}

func colorRed(value string) string {
	return colorizeTerminalString(value, "31")
}

func colorYellow(value string) string {
	return colorizeTerminalString(value, "33")
}

func colorizeTerminalString(value, code string) string {
	if !preflightColorEnabled() {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func colorizePreflight(value, code string, noColor bool) string {
	if noColor || !preflightColorEnabled() {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func preflightColorEnabled() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb")
}

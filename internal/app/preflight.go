package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
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

type ldapPreflightValidator struct {
	opts   discovery.LDAPOptions
	logger *logx.Logger
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

	writePreflightLine(hooks.out, colorYellow("Checking credentials..."))
	for _, validator := range validators {
		if err := validator.Validate(ctx); err != nil {
			writePreflightLine(hooks.out, colorRed("Credential validation failed!"))
			writePreflightLine(hooks.out, err.Error())
			return err
		}
	}
	writePreflightLine(hooks.out, colorGreen("Credentials are valid!"))

	if !useInteractiveTUI {
		return nil
	}
	return hooks.sleep(ctx, preflightDelay)
}

func scanPreflightValidators(cfg config.Config, logger *logx.Logger) []preflightValidator {
	validators := make([]preflightValidator, 0, 1)
	if requiresLDAPPreflight(cfg.Scan) {
		validators = append(validators, ldapPreflightValidator{
			opts: discovery.LDAPOptions{
				Username:         cfg.Scan.Username,
				Password:         cfg.Scan.Password,
				Domain:           cfg.Scan.Domain,
				DomainController: cfg.Scan.DomainController,
				BaseDN:           cfg.Scan.BaseDN,
				Timeout:          cfg.Scan.ReachabilityTimeout(),
			},
			logger: logger,
		})
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

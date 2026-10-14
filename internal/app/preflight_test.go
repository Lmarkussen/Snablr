package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"snablr/internal/config"
	"snablr/internal/discovery"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

type stubPreflightValidator struct {
	err error
}

func (v stubPreflightValidator) Name() string {
	return "credentials"
}

func (v stubPreflightValidator) Validate(context.Context) error {
	return v.err
}

type noopSink struct{}

func (noopSink) WriteFinding(scanner.Finding) error { return nil }
func (noopSink) Close() error                       { return nil }

func TestRunScanPreflightSuccessInteractiveSleepsBeforeTUI(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	sleepCalls := 0

	err := runScanPreflightWithHooks(context.Background(), config.Config{}, true, nil, preflightHooks{
		out: &buf,
		sleep: func(ctx context.Context, duration time.Duration) error {
			sleepCalls++
			if duration != preflightDelay {
				t.Fatalf("unexpected preflight delay: %s", duration)
			}
			return nil
		},
		validators: func(config.Config, *logx.Logger) []preflightValidator {
			return []preflightValidator{stubPreflightValidator{}}
		},
	})
	if err != nil {
		t.Fatalf("runScanPreflightWithHooks returned error: %v", err)
	}
	if sleepCalls != 1 {
		t.Fatalf("expected one preflight sleep call, got %d", sleepCalls)
	}
	output := buf.String()
	if !strings.Contains(output, "Checking credentials ...") {
		t.Fatalf("expected preflight output to contain credential check notice, got %q", output)
	}
	if !strings.Contains(output, "Credentials are Valid") {
		t.Fatalf("expected preflight output to contain success notice, got %q", output)
	}
}

func TestRunScanPreflightFailureAbortsWithoutSleep(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	sleepCalls := 0

	err := runScanPreflightWithHooks(context.Background(), config.Config{}, true, nil, preflightHooks{
		out: &buf,
		sleep: func(ctx context.Context, duration time.Duration) error {
			sleepCalls++
			return nil
		},
		validators: func(config.Config, *logx.Logger) []preflightValidator {
			return []preflightValidator{stubPreflightValidator{err: fmt.Errorf("ldap discovery: bind failed")}}
		},
	})
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	if sleepCalls != 0 {
		t.Fatalf("expected no preflight sleep on failure, got %d", sleepCalls)
	}
	output := buf.String()
	if !strings.Contains(output, "Preflight Error") {
		t.Fatalf("expected preflight error banner in preflight output, got %q", output)
	}
	if strings.Contains(output, "ldap discovery: bind failed") {
		t.Fatalf("expected detail to be returned for the CLI, not printed twice, got %q", output)
	}
	if !strings.Contains(err.Error(), "ldap discovery: bind failed") {
		t.Fatalf("expected concrete failure reason in returned error, got %v", err)
	}
}

type timeoutPreflightError struct{}

func (timeoutPreflightError) Error() string   { return "dial tcp synthetic.invalid:445: i/o timeout" }
func (timeoutPreflightError) Timeout() bool   { return true }
func (timeoutPreflightError) Temporary() bool { return true }

var _ net.Error = timeoutPreflightError{}

func TestClassifyPreflightFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		kind   preflightFailureKind
		status string
		detail string
	}{
		{
			name:   "timeout",
			err:    &smbPreflightError{host: "synthetic-host", err: timeoutPreflightError{}},
			kind:   preflightTargetUnreachable,
			status: "Target Unreachable",
			detail: "synthetic-host: SMB connection timed out",
		},
		{
			name:   "wrapped transport timeout",
			err:    &smbPreflightError{host: "synthetic-host", err: errors.New("connection error: dial tcp synthetic-host:445: i/o timeout")},
			kind:   preflightTargetUnreachable,
			status: "Target Unreachable",
			detail: "synthetic-host: SMB connection timed out",
		},
		{
			name:   "connection refused",
			err:    &smbPreflightError{host: "synthetic-host", err: syscall.ECONNREFUSED},
			kind:   preflightTargetUnreachable,
			status: "Target Unreachable",
			detail: "synthetic-host: SMB service is not reachable on port 445",
		},
		{
			name:   "no route",
			err:    &smbPreflightError{host: "synthetic-host", err: syscall.ENETUNREACH},
			kind:   preflightTargetUnreachable,
			status: "Target Unreachable",
			detail: "synthetic-host: SMB service is not reachable on port 445",
		},
		{
			name:   "rejected credentials",
			err:    &smbPreflightError{host: "synthetic-host", err: errors.New("SMB error: STATUS_LOGON_FAILURE")},
			kind:   preflightInvalidCredentials,
			status: "Credentials Invalid",
			detail: "synthetic-host: SMB credentials were rejected",
		},
		{
			name:   "protocol failure",
			err:    &smbPreflightError{host: "synthetic-host", err: errors.New("invalid SMB negotiate response")},
			kind:   preflightProtocolError,
			status: "Preflight Error",
			detail: "synthetic-host: SMB protocol negotiation failed",
		},
		{
			name:   "ldap stronger auth",
			err:    errors.New("ldap discovery: strongerAuthRequired; integrity checking required"),
			kind:   preflightSecurityRequirement,
			status: "Preflight Error",
			detail: "LDAP requires stronger authentication or signing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := classifyPreflightFailure(test.err)
			if failure.kind != test.kind {
				t.Fatalf("classification kind = %q, want %q", failure.kind, test.kind)
			}
			if got := preflightStatus(failure.kind); got != test.status {
				t.Fatalf("status = %q, want %q", got, test.status)
			}
			if failure.Error() != test.detail {
				t.Fatalf("detail = %q, want %q", failure.Error(), test.detail)
			}
		})
	}
}

func TestPreflightFailureStatusDoesNotDuplicateDetail(t *testing.T) {
	failure := classifyPreflightFailure(&smbPreflightError{
		host: "synthetic-host",
		err:  timeoutPreflightError{},
	})
	if strings.Count(failure.Error(), "synthetic-host") != 1 {
		t.Fatalf("expected one concise target detail, got %q", failure.Error())
	}
	if strings.Contains(failure.Error(), "i/o timeout") {
		t.Fatalf("expected raw dial detail to stay out of normal error text, got %q", failure.Error())
	}
}

func TestRunScanPreflightNoTUISkipsDelay(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	sleepCalls := 0

	err := runScanPreflightWithHooks(context.Background(), config.Config{}, false, nil, preflightHooks{
		out: &buf,
		sleep: func(ctx context.Context, duration time.Duration) error {
			sleepCalls++
			return nil
		},
		validators: func(config.Config, *logx.Logger) []preflightValidator {
			return []preflightValidator{stubPreflightValidator{}}
		},
	})
	if err != nil {
		t.Fatalf("runScanPreflightWithHooks returned error: %v", err)
	}
	if sleepCalls != 0 {
		t.Fatalf("expected no preflight delay when TUI is disabled, got %d", sleepCalls)
	}
}

func TestRunScanPreflightNoColorPreservesStatusText(t *testing.T) {
	var buf bytes.Buffer
	err := runScanPreflightWithHooks(context.Background(), config.Config{Output: config.OutputConfig{NoColor: true}}, false, nil, preflightHooks{
		out: &buf,
		validators: func(config.Config, *logx.Logger) []preflightValidator {
			return []preflightValidator{stubPreflightValidator{}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !strings.Contains(output, "Checking credentials ...") || !strings.Contains(output, "Credentials are Valid") {
		t.Fatalf("missing no-color preflight status: %q", output)
	}
	if strings.Contains(output, "\x1b[") {
		t.Fatalf("no-color preflight emitted ANSI escape: %q", output)
	}
}

func TestScanPreflightValidatorsIncludeSMBForExplicitTargets(t *testing.T) {
	validators := scanPreflightValidators(config.Config{Scan: config.ScanConfig{
		Targets:  []string{"fileserver.example.test"},
		Username: "synthetic-user",
		Password: "SyntheticPassword482!",
		SMBAuth:  "password",
	}}, nil)
	if len(validators) != 1 {
		t.Fatalf("expected one SMB preflight validator, got %d", len(validators))
	}
	if _, ok := validators[0].(smbPreflightValidator); !ok {
		t.Fatalf("expected SMB preflight validator, got %T", validators[0])
	}
}

func TestRequiresLDAPPreflight(t *testing.T) {
	t.Parallel()

	if !requiresLDAPPreflight(config.ScanConfig{
		Username:         "user",
		Password:         "pass",
		DomainController: "DIRECTORY01.TEST.LOCAL",
	}) {
		t.Fatal("expected LDAP preflight when no explicit targets are supplied")
	}
	if !requiresLDAPPreflight(config.ScanConfig{
		Targets:          []string{"FILE01.TEST.LOCAL"},
		DiscoverDFS:      true,
		DomainController: "DIRECTORY01.TEST.LOCAL",
	}) {
		t.Fatal("expected LDAP preflight when DFS discovery is enabled")
	}
	if requiresLDAPPreflight(config.ScanConfig{
		Targets: []string{"FILE01.TEST.LOCAL"},
		NoLDAP:  true,
	}) {
		t.Fatal("did not expect LDAP preflight for direct-target scan without LDAP/DFS")
	}
}

func TestScanPreflightValidatorsPassLDAPAuthOptions(t *testing.T) {
	t.Parallel()

	validators := scanPreflightValidators(config.Config{
		Scan: config.ScanConfig{
			AuthMode:         discovery.AuthModeKerberos,
			KerberosCCache:   "test.ccache",
			LDAPSPN:          "ldap/DIRECTORY01.TEST.LOCAL",
			DomainController: "DIRECTORY01.TEST.LOCAL",
		},
	}, nil)
	if len(validators) != 1 {
		t.Fatalf("expected one preflight validator, got %d", len(validators))
	}
	validator, ok := validators[0].(ldapPreflightValidator)
	if !ok {
		t.Fatalf("expected ldap preflight validator, got %T", validators[0])
	}
	if validator.opts.AuthMode != discovery.AuthModeKerberos || validator.opts.KerberosCCache != "test.ccache" || validator.opts.LDAPSPN != "ldap/DIRECTORY01.TEST.LOCAL" {
		t.Fatalf("ldap auth options were not propagated: %#v", validator.opts)
	}
}

func TestRunScanPreflightFailureStopsBeforeWriterAndDiscovery(t *testing.T) {
	origPreflight := runScanPreflightFunc
	origWriter := newOutputWriterFunc
	origResolve := resolveTargetsFunc
	defer func() {
		runScanPreflightFunc = origPreflight
		newOutputWriterFunc = origWriter
		resolveTargetsFunc = origResolve
	}()

	preflightCalled := false
	writerCalled := false
	resolveCalled := false

	runScanPreflightFunc = func(ctx context.Context, cfg config.Config, useInteractiveTUI bool, logger *logx.Logger) error {
		preflightCalled = true
		return fmt.Errorf("invalid credentials")
	}
	newOutputWriterFunc = func(cfg config.OutputConfig) (scanner.FindingSink, error) {
		writerCalled = true
		return noopSink{}, nil
	}
	resolveTargetsFunc = func(ctx context.Context, cfg config.ScanConfig, logger discovery.Logger, recorder metrics.Recorder) (discovery.PipelineResult, error) {
		resolveCalled = true
		return discovery.PipelineResult{}, nil
	}

	err := RunScan(context.Background(), ScanOptions{
		Username:         "user",
		Password:         "pass",
		Domain:           "TEST.LOCAL",
		DomainController: "DIRECTORY01.TEST.LOCAL",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid credentials") {
		t.Fatalf("expected preflight failure to be returned, got %v", err)
	}
	if !preflightCalled {
		t.Fatal("expected preflight to run")
	}
	if writerCalled {
		t.Fatal("did not expect output writer creation after preflight failure")
	}
	if resolveCalled {
		t.Fatal("did not expect target discovery after preflight failure")
	}
}

func TestRunScanResolvesTargetsBeforeCreatingWriter(t *testing.T) {
	origPreflight := runScanPreflightFunc
	origWriter := newOutputWriterFunc
	origResolve := resolveTargetsFunc
	defer func() {
		runScanPreflightFunc = origPreflight
		newOutputWriterFunc = origWriter
		resolveTargetsFunc = origResolve
	}()

	preflightCalled := false
	writerCalled := false
	resolveCalled := false

	runScanPreflightFunc = func(ctx context.Context, cfg config.Config, useInteractiveTUI bool, logger *logx.Logger) error {
		preflightCalled = true
		return nil
	}
	resolveTargetsFunc = func(ctx context.Context, cfg config.ScanConfig, logger discovery.Logger, recorder metrics.Recorder) (discovery.PipelineResult, error) {
		if writerCalled {
			t.Fatal("writer should not be created before target resolution completes")
		}
		resolveCalled = true
		return discovery.PipelineResult{}, fmt.Errorf("stop after discovery")
	}
	newOutputWriterFunc = func(cfg config.OutputConfig) (scanner.FindingSink, error) {
		writerCalled = true
		return noopSink{}, nil
	}

	err := RunScan(context.Background(), ScanOptions{
		Username: "user",
		Password: "pass",
		Targets:  []string{"FILE01.TEST.LOCAL"},
	})
	if err == nil || !strings.Contains(err.Error(), "stop after discovery") {
		t.Fatalf("expected synthetic discovery stop, got %v", err)
	}
	if !preflightCalled {
		t.Fatal("expected preflight to run")
	}
	if !resolveCalled {
		t.Fatal("expected target resolution to run")
	}
	if writerCalled {
		t.Fatal("did not expect writer creation after synthetic discovery failure")
	}
}

package app

import (
	"bytes"
	"context"
	"fmt"
	"strings"
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
	if !strings.Contains(output, "Checking credentials...") {
		t.Fatalf("expected preflight output to contain credential check notice, got %q", output)
	}
	if !strings.Contains(output, "Credentials are valid!") {
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
	if !strings.Contains(output, "Credential validation failed!") {
		t.Fatalf("expected failure banner in preflight output, got %q", output)
	}
	if !strings.Contains(output, "ldap discovery: bind failed") {
		t.Fatalf("expected concrete failure reason in preflight output, got %q", output)
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

func TestRequiresLDAPPreflight(t *testing.T) {
	t.Parallel()

	if !requiresLDAPPreflight(config.ScanConfig{
		Username:         "user",
		Password:         "pass",
		DomainController: "dc01.example.local",
	}) {
		t.Fatal("expected LDAP preflight when no explicit targets are supplied")
	}
	if !requiresLDAPPreflight(config.ScanConfig{
		Targets:          []string{"10.0.0.5"},
		DiscoverDFS:      true,
		DomainController: "dc01.example.local",
	}) {
		t.Fatal("expected LDAP preflight when DFS discovery is enabled")
	}
	if requiresLDAPPreflight(config.ScanConfig{
		Targets: []string{"10.0.0.5"},
		NoLDAP:  true,
	}) {
		t.Fatal("did not expect LDAP preflight for direct-target scan without LDAP/DFS")
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
		Domain:           "example.local",
		DomainController: "dc01.example.local",
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
		Targets:  []string{"10.0.0.5"},
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

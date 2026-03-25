package wiminspect

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	listPaths     []string
	extractByPath map[string][]byte
	extractCalls  []string
	lookPathErr   error
}

func (f *fakeRunner) LookPath(string) (string, error) {
	if f.lookPathErr != nil {
		return "", f.lookPathErr
	}
	return "/usr/bin/wimlib-imagex", nil
}

func (f *fakeRunner) ListPaths(context.Context, string) ([]string, error) {
	return append([]string{}, f.listPaths...), nil
}

func (f *fakeRunner) ExtractFile(_ context.Context, _ string, memberPath string) ([]byte, error) {
	f.extractCalls = append(f.extractCalls, memberPath)
	return append([]byte{}, f.extractByPath[memberPath]...), nil
}

func TestShouldInspectWIM(t *testing.T) {
	opts := Options{Enabled: true, AutoWIMMaxSize: 8 * 1024 * 1024}
	ok, reason := ShouldInspect(Candidate{Name: "install.wim", Extension: ".wim", Size: 1024}, opts)
	if !ok || reason != "" {
		t.Fatalf("expected inspectable wim, got ok=%v reason=%q", ok, reason)
	}

	ok, reason = ShouldInspect(Candidate{Name: "install.wim", Extension: ".wim", Size: 16 * 1024 * 1024}, opts)
	if ok || !strings.Contains(reason, "automatic inspection limit") {
		t.Fatalf("expected large wim skip, got ok=%v reason=%q", ok, reason)
	}
}

func TestInspectSelectivelyExtractsTargetedContent(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()

	fake := &fakeRunner{
		listPaths: []string{
			"/Windows/System32/config/SAM",
			"/Windows/System32/config/SYSTEM",
			"/Windows/Panther/unattend.xml",
			"/Sources/install.esd",
			"/Deploy/Control/bootstrap.ini",
		},
		extractByPath: map[string][]byte{
			"/windows/panther/unattend.xml":  []byte("<unattend><Password>Winter2025!</Password></unattend>"),
			"/deploy/control/bootstrap.ini": []byte("[Settings]\nUserPassword=Winter2025!\n"),
		},
	}
	runner = fake

	result, err := Inspect([]byte("demo"), Options{
		Enabled:        true,
		AutoWIMMaxSize: 8 * 1024 * 1024,
		MaxMembers:     8,
		MaxMemberBytes: 1024,
		MaxTotalBytes:  2048,
	})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if !result.Inspected || !result.InspectedLocally {
		t.Fatalf("expected inspected local result, got %#v", result)
	}
	if len(result.Members) != 4 {
		t.Fatalf("expected 4 targeted members, got %#v", result.Members)
	}
	if len(fake.extractCalls) != 2 {
		t.Fatalf("expected only text deployment artifacts to be extracted, got %#v", fake.extractCalls)
	}
}

func TestInspectSkipsWhenToolMissing(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = &fakeRunner{lookPathErr: errors.New("missing")}

	if _, err := Inspect([]byte("demo"), Options{Enabled: true}); err == nil {
		t.Fatal("expected error when wimlib-imagex is unavailable")
	}
}

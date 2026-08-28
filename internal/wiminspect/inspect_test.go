package wiminspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"snablr/internal/artifact"
)

type fakeRunner struct {
	images        []int
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

func (f *fakeRunner) ListImages(context.Context, string) ([]int, error) {
	if len(f.images) == 0 {
		return []int{1}, nil
	}
	return append([]int{}, f.images...), nil
}

func (f *fakeRunner) ListPaths(context.Context, string, int) ([]string, error) {
	return append([]string{}, f.listPaths...), nil
}

func (f *fakeRunner) ExtractFile(_ context.Context, _ string, _ int, memberPath string, dst io.Writer) error {
	f.extractCalls = append(f.extractCalls, memberPath)
	_, err := io.Copy(dst, bytes.NewReader(f.extractByPath[strings.ToLower(memberPath)]))
	return err
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
			"/windows/system32/config/sam":    []byte("sam-binary"),
			"/windows/system32/config/system": []byte("system-binary"),
			"/windows/panther/unattend.xml":   []byte("<unattend><Password>Winter2025!</Password></unattend>"),
			"/deploy/control/bootstrap.ini":   []byte("[Settings]\nUserPassword=Winter2025!\n"),
		},
	}
	runner = fake

	result, err := Inspect(context.Background(), []byte("demo"), Options{
		Enabled:        true,
		AutoWIMMaxSize: 8 * 1024 * 1024,
		MaxMembers:     8,
		MaxMemberBytes: 1024,
		MaxTotalBytes:  2048,
	}, artifact.Origin{ContainerPath: "image.wim"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if !result.Inspected || !result.InspectedLocally {
		t.Fatalf("expected inspected local result, got %#v", result)
	}
	if len(result.Members) != 2 {
		t.Fatalf("expected 2 text targeted members, got %#v", result.Members)
	}
	if len(fake.extractCalls) != 4 {
		t.Fatalf("expected text and binary targeted artifacts to be extracted, got %#v", fake.extractCalls)
	}
	if len(result.BinaryMembers) != 2 || result.BinaryMembers[0].Size == 0 {
		t.Fatalf("unexpected binary members: %#v", result.BinaryMembers)
	}
	reader, err := result.BinaryMembers[0].Artifact.Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(data) != "sam-binary" {
		t.Fatalf("unexpected extracted bytes %q: %v", data, err)
	}
	if result.Cleanup != nil {
		for _, member := range result.BinaryMembers {
			_ = member.Artifact.Close()
		}
		_ = result.Cleanup()
	}
}

func TestInspectSkipsWhenToolMissing(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = &fakeRunner{lookPathErr: errors.New("missing")}

	if _, err := Inspect(context.Background(), []byte("demo"), Options{Enabled: true}, artifact.Origin{}); err == nil {
		t.Fatal("expected error when wimlib-imagex is unavailable")
	}
}

func TestInspectPreservesImageIndexAndSeparatesBinaryMembers(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	fake := &fakeRunner{
		images:        []int{1, 2},
		listPaths:     []string{"/Windows/System32/config/SAM"},
		extractByPath: map[string][]byte{"/windows/system32/config/sam": []byte("sam")},
	}
	runner = fake
	result, err := Inspect(context.Background(), []byte("demo"), Options{MaxImages: 2}, artifact.Origin{ContainerPath: "outer.wim"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Members) != 0 || len(result.BinaryMembers) != 2 {
		t.Fatalf("unexpected split: text=%d binary=%d", len(result.Members), len(result.BinaryMembers))
	}
	if result.BinaryMembers[0].Artifact.Origin().ImageIndex != 1 || result.BinaryMembers[1].Artifact.Origin().ImageIndex != 2 {
		t.Fatalf("image indexes not preserved")
	}
	closeTestBinaryMembers(result)
	_ = result.Cleanup()
}

func TestInspectEnforcesBinaryCountAndTotalLimits(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	fake := &fakeRunner{
		images:    []int{1},
		listPaths: []string{"/Windows/System32/config/SAM", "/Windows/System32/config/SYSTEM"},
		extractByPath: map[string][]byte{
			"/windows/system32/config/sam":    []byte("1234"),
			"/windows/system32/config/system": []byte("5678"),
		},
	}
	runner = fake
	result, err := Inspect(context.Background(), []byte("demo"), Options{MaxBinaryArtifacts: 1, MaxBinaryBytes: 4}, artifact.Origin{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.BinaryMembers) != 1 || result.BinaryMembers[0].Size != 4 {
		t.Fatalf("limits not enforced: %#v", result.BinaryMembers)
	}
	closeTestBinaryMembers(result)
	_ = result.Cleanup()
}

func TestInspectSkipsOversizedBinaryMember(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = &fakeRunner{
		listPaths:     []string{"/Windows/System32/config/SAM"},
		extractByPath: map[string][]byte{"/windows/system32/config/sam": []byte("12345")},
	}
	result, err := Inspect(context.Background(), []byte("demo"), Options{MaxSAMBytes: 4}, artifact.Origin{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.BinaryMembers) != 0 {
		t.Fatalf("oversized binary was retained: %#v", result.BinaryMembers)
	}
	closeTestBinaryMembers(result)
	_ = result.Cleanup()
}

func closeTestBinaryMembers(result Result) {
	for _, member := range result.BinaryMembers {
		_ = member.Artifact.Close()
	}
}

type cancelRunner struct{}

func (cancelRunner) LookPath(string) (string, error)                          { return "/usr/bin/wimlib-imagex", nil }
func (cancelRunner) ListImages(ctx context.Context, _ string) ([]int, error)  { return nil, ctx.Err() }
func (cancelRunner) ListPaths(context.Context, string, int) ([]string, error) { return nil, nil }
func (cancelRunner) ExtractFile(ctx context.Context, _ string, _ int, _ string, _ io.Writer) error {
	return ctx.Err()
}

func TestInspectPropagatesCancellation(t *testing.T) {
	orig := runner
	defer func() { runner = orig }()
	runner = cancelRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(ctx, []byte("demo"), Options{}, artifact.Origin{}); err == nil {
		t.Fatal("expected cancellation")
	}
}

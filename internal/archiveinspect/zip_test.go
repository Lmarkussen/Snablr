package archiveinspect

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestShouldInspectZIPHonorsDefaultAndLargeOverrides(t *testing.T) {
	t.Parallel()

	defaults := Options{
		Enabled:        true,
		AutoZIPMaxSize: 10 * 1024 * 1024,
		MaxZIPSize:     10 * 1024 * 1024,
		MaxMembers:     64,
		MaxMemberBytes: 512 * 1024,
	}

	if ok, reason := ShouldInspect(Candidate{Name: "loot.zip", Extension: ".zip", Size: 1024}, defaults); !ok || reason != "" {
		t.Fatalf("expected small zip to be inspected, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := ShouldInspect(Candidate{Name: "large.zip", Extension: ".zip", Size: 11 * 1024 * 1024}, defaults); ok || reason == "" {
		t.Fatalf("expected large zip to be skipped by default, got ok=%v reason=%q", ok, reason)
	}

	defaults.AllowLargeZIPs = true
	defaults.MaxZIPSize = 20 * 1024 * 1024
	if ok, reason := ShouldInspect(Candidate{Name: "large.zip", Extension: ".zip", Size: 11 * 1024 * 1024}, defaults); !ok || reason != "" {
		t.Fatalf("expected large zip override to allow inspection, got ok=%v reason=%q", ok, reason)
	}
}

func TestInspectZIPSkipsNestedAndBinaryMembers(t *testing.T) {
	t.Parallel()

	inner := buildZIPBytes(t, map[string][]byte{
		"secret.txt": []byte("password=Winter2025!"),
	})
	content := buildZIPBytes(t, map[string][]byte{
		"nested/archive.zip": inner,
		"image.png":          append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
		"config/app.env":     []byte("db_password=Winter2025!\n"),
	})

	result, err := InspectZIP(content, Options{
		Enabled:                  true,
		AutoZIPMaxSize:           10 * 1024 * 1024,
		MaxZIPSize:               10 * 1024 * 1024,
		MaxMembers:               64,
		MaxMemberBytes:           512 * 1024,
		MaxTotalUncompressed:     4 * 1024 * 1024,
		InspectExtensionlessText: true,
	}, map[string]struct{}{
		".env": {},
		".txt": {},
	})
	if err != nil {
		t.Fatalf("InspectZIP returned error: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].Path != "config/app.env" {
		t.Fatalf("expected only the text env member, got %#v", result.Members)
	}
}

func TestInspectZIPHonorsMemberAndTotalLimits(t *testing.T) {
	t.Parallel()

	content := buildZIPBytes(t, map[string][]byte{
		"one.txt":   []byte("password=Winter2025!\n"),
		"two.txt":   []byte("password=Winter2025!\n"),
		"three.txt": bytes.Repeat([]byte("A"), 1024),
	})

	result, err := InspectZIP(content, Options{
		Enabled:                  true,
		AutoZIPMaxSize:           10 * 1024 * 1024,
		MaxZIPSize:               10 * 1024 * 1024,
		MaxMembers:               1,
		MaxMemberBytes:           128,
		MaxTotalUncompressed:     64,
		InspectExtensionlessText: true,
	}, map[string]struct{}{
		".txt": {},
	})
	if err != nil {
		t.Fatalf("InspectZIP returned error: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].Path == "three.txt" {
		t.Fatalf("expected archive limits to stop after first small member, got %#v", result.Members)
	}
}

func buildZIPBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range members {
		fileWriter, err := writer.Create(name)
		if err != nil {
			t.Fatalf("Create(%s) returned error: %v", name, err)
		}
		if _, err := fileWriter.Write(content); err != nil {
			t.Fatalf("Write(%s) returned error: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	return buf.Bytes()
}

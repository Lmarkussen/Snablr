package archiveinspect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"
	"unicode/utf16"
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

	result, err := InspectZIP(content, ".zip", Options{
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

	result, err := InspectZIP(content, ".zip", Options{
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

func TestInspectZIPRecognizesUTF16TextMembers(t *testing.T) {
	t.Parallel()

	content := buildZIPBytes(t, map[string][]byte{
		"docs/norwegian.txt": utf16LEArchiveText("Passord: Vår2026!\nBruker=señor\n"),
		"image.png":          append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
	})

	result, err := InspectZIP(content, ".zip", Options{
		Enabled:                  true,
		AutoZIPMaxSize:           10 * 1024 * 1024,
		MaxZIPSize:               10 * 1024 * 1024,
		MaxMembers:               64,
		MaxMemberBytes:           512 * 1024,
		MaxTotalUncompressed:     4 * 1024 * 1024,
		InspectExtensionlessText: true,
	}, map[string]struct{}{
		".txt": {},
	})
	if err != nil {
		t.Fatalf("InspectZIP returned error: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].Path != "docs/norwegian.txt" {
		t.Fatalf("expected UTF-16 text member to be retained, got %#v", result.Members)
	}
}

func TestShouldInspectSupportsOfficeOpenXMLContainers(t *testing.T) {
	t.Parallel()

	opts := Options{
		Enabled:        true,
		AutoZIPMaxSize: 10 * 1024 * 1024,
		MaxZIPSize:     10 * 1024 * 1024,
		MaxMembers:     64,
		MaxMemberBytes: 512 * 1024,
	}

	for _, ext := range []string{".docx", ".xlsx", ".pptx"} {
		if ok, reason := ShouldInspect(Candidate{Name: "sample" + ext, Extension: ext, Size: 1024}, opts); !ok || reason != "" {
			t.Fatalf("expected %s to be inspected, got ok=%v reason=%q", ext, ok, reason)
		}
	}
}

func TestShouldInspectTARHonorsDefaultLimit(t *testing.T) {
	t.Parallel()

	opts := Options{
		Enabled:        true,
		AutoTARMaxSize: 10 * 1024 * 1024,
		MaxTARSize:     10 * 1024 * 1024,
		MaxMembers:     64,
		MaxMemberBytes: 512 * 1024,
	}
	for _, ext := range []string{".tar", ".tar.gz", ".tgz"} {
		if ok, reason := ShouldInspect(Candidate{Name: "sample" + ext, Extension: ext, Size: 1024}, opts); !ok || reason != "" {
			t.Fatalf("expected %s to be inspected, got ok=%v reason=%q", ext, ok, reason)
		}
	}
	if ok, reason := ShouldInspect(Candidate{Name: "large.tar.gz", Extension: ".gz", Size: 11 * 1024 * 1024}, opts); ok || reason == "" {
		t.Fatalf("expected large tar.gz to be skipped by default, got ok=%v reason=%q", ok, reason)
	}
}

func TestInspectTARSkipsNestedAndBinaryMembers(t *testing.T) {
	t.Parallel()

	inner := buildTARBytes(t, ".tar", map[string][]byte{
		"secret.txt": []byte("password=Winter2025!"),
	})
	content := buildTARBytes(t, ".tar.gz", map[string][]byte{
		"nested/archive.tar": inner,
		"image.png":          append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
		"config/app.env":     []byte("db_password=Winter2025!\n"),
	})

	result, err := InspectTAR(content, ".tar.gz", Options{
		Enabled:                  true,
		AutoTARMaxSize:           10 * 1024 * 1024,
		MaxTARSize:               10 * 1024 * 1024,
		MaxMembers:               64,
		MaxMemberBytes:           512 * 1024,
		MaxTotalUncompressed:     4 * 1024 * 1024,
		InspectExtensionlessText: true,
	}, map[string]struct{}{
		".env": {},
		".txt": {},
	})
	if err != nil {
		t.Fatalf("InspectTAR returned error: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].Path != "config/app.env" {
		t.Fatalf("expected only the text env member, got %#v", result.Members)
	}
}

func TestInspectTARHonorsMemberAndTotalLimits(t *testing.T) {
	t.Parallel()

	content := buildTARBytes(t, ".tgz", map[string][]byte{
		"one.txt":   []byte("password=Winter2025!\n"),
		"two.txt":   []byte("password=Winter2025!\n"),
		"three.txt": bytes.Repeat([]byte("A"), 1024),
	})
	result, err := InspectTAR(content, ".tgz", Options{
		Enabled:                  true,
		AutoTARMaxSize:           10 * 1024 * 1024,
		MaxTARSize:               10 * 1024 * 1024,
		MaxMembers:               1,
		MaxMemberBytes:           128,
		MaxTotalUncompressed:     64,
		InspectExtensionlessText: true,
	}, map[string]struct{}{".txt": {}})
	if err != nil {
		t.Fatalf("InspectTAR returned error: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].Path == "three.txt" {
		t.Fatalf("expected tar limits to stop after first small member, got %#v", result.Members)
	}
}

func TestInspectZIPOfficeFiltersToRelevantXMLMembers(t *testing.T) {
	t.Parallel()

	content := buildZIPBytes(t, map[string][]byte{
		"word/document.xml":     []byte(`<w:document><w:body><w:t>password=Winter2025!</w:t></w:body></w:document>`),
		"word/header1.xml":      []byte(`<w:hdr><w:t>client_secret=LAB_ONLY</w:t></w:hdr>`),
		"word/media/image1.png": append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
		"custom/item1.xml":      []byte(`<customXml>ignored</customXml>`),
	})

	result, err := InspectZIP(content, ".docx", Options{
		Enabled:              true,
		AutoZIPMaxSize:       10 * 1024 * 1024,
		MaxZIPSize:           10 * 1024 * 1024,
		MaxMembers:           64,
		MaxMemberBytes:       512 * 1024,
		MaxTotalUncompressed: 4 * 1024 * 1024,
	}, map[string]struct{}{".xml": {}})
	if err != nil {
		t.Fatalf("InspectZIP returned error: %v", err)
	}
	if len(result.Members) != 2 {
		t.Fatalf("expected only relevant Office XML members, got %#v", result.Members)
	}
	for _, member := range result.Members {
		if member.Path != "word/document.xml" && member.Path != "word/header1.xml" {
			t.Fatalf("unexpected office member included: %#v", member)
		}
	}
}

func utf16LEArchiveText(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	out := make([]byte, 0, len(encoded)*2+2)
	out = append(out, 0xFF, 0xFE)
	buf := make([]byte, 2)
	for _, code := range encoded {
		binary.LittleEndian.PutUint16(buf, code)
		out = append(out, buf...)
	}
	return out
}

func TestInspectZIPExtractsOfficeXMLText(t *testing.T) {
	t.Parallel()

	content := buildZIPBytes(t, map[string][]byte{
		"word/document.xml": []byte(`<w:document><w:body><w:p><w:r><w:t>service_account=svc_backup</w:t></w:r></w:p><w:p><w:r><w:t>password=FAKE_DB_PASSWORD_001</w:t></w:r></w:p></w:body></w:document>`),
	})

	result, err := InspectZIP(content, ".docx", Options{
		Enabled:              true,
		AutoZIPMaxSize:       10 * 1024 * 1024,
		MaxZIPSize:           10 * 1024 * 1024,
		MaxMembers:           64,
		MaxMemberBytes:       512 * 1024,
		MaxTotalUncompressed: 4 * 1024 * 1024,
	}, map[string]struct{}{".xml": {}})
	if err != nil {
		t.Fatalf("InspectZIP returned error: %v", err)
	}
	if len(result.Members) != 1 {
		t.Fatalf("expected one office member, got %#v", result.Members)
	}
	got := string(result.Members[0].Content)
	if got != "service_account=svc_backup\npassword=FAKE_DB_PASSWORD_001\n" {
		t.Fatalf("expected extracted Office text, got %q", got)
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

func buildTARBytes(t *testing.T, ext string, members map[string][]byte) []byte {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range members {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%s) returned error: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("Write(%s) returned error: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close tar writer returned error: %v", err)
	}
	if ext == ".tar" {
		return tarBuf.Bytes()
	}
	var gzipBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzipBuf, gzip.NoCompression)
	if err != nil {
		t.Fatalf("NewWriterLevel returned error: %v", err)
	}
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write returned error: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close returned error: %v", err)
	}
	return gzipBuf.Bytes()
}

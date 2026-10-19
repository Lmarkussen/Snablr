package seed

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestGenerateExpandedCorpusIsDeterministicAndBounded(t *testing.T) {
	opts := GenerateOptions{Expanded: true, SeedPrefix: "Expanded", MaxFiles: 12000, Depth: 12, RandomSeed: 42}
	first, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) || len(first) < 10000 {
		t.Fatalf("expanded file count first=%d second=%d", len(first), len(second))
	}
	for index := range first {
		if FullPath(first[index]) != FullPath(second[index]) || string(first[index].Content) != string(second[index].Content) {
			t.Fatalf("expanded output is not deterministic at index %d", index)
		}
	}
	wantPaths := []string{
		"Expanded/SkipFolder-Test/1/2/3/Nested-A",
		"Expanded/SkipFolder-Test/1/2/30",
		"Expanded/SkipFolder-Test/1/2/4",
		"Expanded/DeepTree/Branch-01/Level-01",
		"Expanded/WideTree/Folder-0001",
		"Expanded/Evidence-Fixtures/PowerShell",
		"Expanded/Evidence-Fixtures/Hashes",
		"Expanded/Evidence-Fixtures/SCCM",
	}
	for _, want := range wantPaths {
		found := false
		for _, file := range first {
			if strings.HasPrefix(FullPath(file), want+"/") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expanded corpus missing %s", want)
		}
	}
}

func TestGenerateExpandedCorpusIncludesValidContainerFixtures(t *testing.T) {
	files, err := Generate(GenerateOptions{Expanded: true, SeedPrefix: "Expanded", MaxFiles: 12000, Depth: 12})
	if err != nil {
		t.Fatal(err)
	}
	wantMembers := map[string]string{
		"valid-credentials.zip":  "configs/credentials.ini",
		"valid-credentials.docx": "word/document.xml",
		"valid-credentials.xlsx": "xl/sharedStrings.xml",
		"benign-notes.docx":      "word/document.xml",
		"benign-inventory.xlsx":  "xl/sharedStrings.xml",
		"valid-benign.zip":       "docs/readme.txt",
	}
	found := make(map[string]bool)
	for _, file := range files {
		member, ok := wantMembers[file.Filename]
		if !ok {
			continue
		}
		reader, err := zip.NewReader(bytes.NewReader(file.Content), int64(len(file.Content)))
		if err != nil {
			t.Fatalf("%s is not a valid ZIP container: %v", file.Filename, err)
		}
		for _, entry := range reader.File {
			if entry.Name == member {
				found[file.Filename] = true
				break
			}
		}
		if !strings.HasSuffix(file.ExpectedPath, "!"+member) {
			t.Fatalf("%s expected member provenance=%q", file.Filename, file.ExpectedPath)
		}
	}
	for filename := range wantMembers {
		if !found[filename] {
			t.Fatalf("expanded corpus missing valid member fixture %s", filename)
		}
	}
	for _, file := range files {
		if file.Filename == "malformed.zip" && zipValid(file.Content) {
			t.Fatal("malformed.zip unexpectedly parsed as a valid container")
		}
	}
}

func zipValid(content []byte) bool {
	_, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	return err == nil
}

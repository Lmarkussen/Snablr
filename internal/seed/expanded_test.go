package seed

import (
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

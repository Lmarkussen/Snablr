package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinderExportUsesCompleteSelectedScopeAndStableRows(t *testing.T) {
	path := makeFixtureDB(t, "only-scan")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "finder.html")
	jsonPath := filepath.Join(dir, "finder.json")
	if err := provider.Export(context.Background(), ExportOptions{HTMLPath: htmlPath, JSONPath: jsonPath}); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Synthetic evidence") {
		t.Fatal("HTML export omitted persisted finding")
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
		Credentials []struct {
			ID int64 `json:"id"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Findings) != 1 || document.Findings[0].ID != "finding:1" {
		t.Fatalf("unexpected finding export: %#v", document.Findings)
	}
	if len(document.Credentials) != 1 {
		t.Fatalf("unexpected credential export: %#v", document.Credentials)
	}
}

func TestFinderExportRejectsExistingDestination(t *testing.T) {
	path := makeFixtureDB(t, "only-scan")
	provider, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	destination := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(destination, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provider.Export(context.Background(), ExportOptions{JSONPath: destination}); err == nil {
		t.Fatal("expected existing export destination to be rejected")
	}
	data, _ := os.ReadFile(destination)
	if string(data) != "keep" {
		t.Fatal("existing export was modified")
	}
}

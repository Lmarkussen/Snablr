package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseAuthTestFlags(t *testing.T, args ...string) (*flag.FlagSet, string, string, bool) {
	t.Helper()
	fs := flag.NewFlagSet("auth-test", flag.ContinueOnError)
	var value, path string
	var prompt bool
	fs.StringVar(&value, "password", "", "")
	fs.StringVar(&value, "pass", "", "")
	fs.StringVar(&path, "password-file", "", "")
	fs.BoolVar(&prompt, "password-prompt", false, "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, value, path, prompt
}

func TestReadPasswordFilePreservesBytesAndConventionalNewlines(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"plain", []byte("synthetic-secret"), "synthetic-secret"},
		{"lf", []byte("synthetic-secret\n"), "synthetic-secret"},
		{"crlf", []byte("synthetic-secret\r\n"), "synthetic-secret"},
		{"spaces", []byte("  synthetic secret  "), "  synthetic secret  "},
		{"unicode", []byte("påss🔐"), "påss🔐"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(p, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readPasswordFile(p)
			if err != nil || got != tt.want {
				t.Fatalf("readPasswordFile() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestReadPasswordFileErrorsAreSafe(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	private := "synthetic-never-in-error"
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxPasswordFileSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(unreadable, []byte(private), 0000); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{missing, empty, dir, large, unreadable} {
		_, err := readPasswordFile(path)
		if err == nil {
			t.Errorf("readPasswordFile(%q) succeeded", path)
		}
		if err != nil && strings.Contains(err.Error(), private) {
			t.Errorf("error exposed password: %v", err)
		}
	}
}

func TestResolvePasswordSourcesAndNonInteractivePrompt(t *testing.T) {
	fs, value, path, prompt := parseAuthTestFlags(t, "--password", "synthetic-value")
	got, err := resolveCLIAuthPassword(value, path, prompt, false, fs, os.Stdin, os.Stderr)
	if err != nil || got != "synthetic-value" {
		t.Fatalf("legacy value: %q, %v", got, err)
	}

	fs, value, path, prompt = parseAuthTestFlags(t, "--password", "synthetic-value", "--password-prompt")
	if _, err := resolveCLIAuthPassword(value, path, prompt, false, fs, os.Stdin, os.Stderr); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v", err)
	}

	fs, value, path, prompt = parseAuthTestFlags(t)
	if _, err := resolveCLIAuthPassword(value, path, prompt, true, fs, os.Stdin, os.Stderr); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("automatic non-terminal prompt error = %v", err)
	}

	fs, value, path, prompt = parseAuthTestFlags(t, "--password-prompt")
	if _, err := resolveCLIAuthPassword(value, path, prompt, false, fs, os.Stdin, os.Stderr); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("explicit non-terminal prompt error = %v", err)
	}
}

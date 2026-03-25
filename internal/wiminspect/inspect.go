package wiminspect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

type cliRunner interface {
	LookPath(string) (string, error)
	ListPaths(context.Context, string) ([]string, error)
	ExtractFile(context.Context, string, string) ([]byte, error)
}

type execRunner struct{}

var runner cliRunner = execRunner{}

func ShouldInspect(candidate Candidate, opts Options) (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(candidate.Extension), ".wim") {
		return false, ""
	}
	if !opts.Enabled {
		return false, "wim inspection disabled"
	}
	if opts.AutoWIMMaxSize > 0 && candidate.Size <= opts.AutoWIMMaxSize {
		return true, ""
	}
	if !opts.AllowLargeWIMs {
		if opts.AutoWIMMaxSize > 0 {
			return false, fmt.Sprintf("wim exceeds automatic inspection limit of %d bytes", opts.AutoWIMMaxSize)
		}
		return false, "wim inspection requires an explicit size limit"
	}
	if opts.MaxWIMSize > 0 && candidate.Size > opts.MaxWIMSize {
		return false, fmt.Sprintf("wim exceeds configured inspection limit of %d bytes", opts.MaxWIMSize)
	}
	return true, ""
}

func Inspect(content []byte, opts Options) (Result, error) {
	if _, err := runner.LookPath("wimlib-imagex"); err != nil {
		return Result{}, fmt.Errorf("wimlib-imagex not available: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "snablr-wiminspect-*.wim")
	if err != nil {
		return Result{}, fmt.Errorf("create temp wim: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return Result{}, fmt.Errorf("write temp wim: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return Result{}, fmt.Errorf("close temp wim: %w", err)
	}

	ctx := context.Background()
	paths, err := runner.ListPaths(ctx, tmpPath)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Inspected:        true,
		InspectedLocally: true,
		Members:          make([]Member, 0),
	}

	totalBytes := int64(0)
	for _, rawPath := range paths {
		displayPath := cleanWIMDisplayPath(rawPath)
		memberPath := normalizeWIMPath(rawPath)
		if memberPath == "" || !isTargetedPath(memberPath) {
			continue
		}
		if opts.MaxMembers > 0 && len(result.Members) >= opts.MaxMembers {
			break
		}

		member := Member{
			Path:      strings.TrimPrefix(displayPath, "/"),
			Name:      path.Base(displayPath),
			Extension: strings.ToLower(filepath.Ext(displayPath)),
		}

		if shouldExtractContent(memberPath) {
			data, err := runner.ExtractFile(ctx, tmpPath, displayPath)
			if err != nil {
				continue
			}
			if opts.MaxMemberBytes > 0 && int64(len(data)) > opts.MaxMemberBytes {
				continue
			}
			if opts.MaxTotalBytes > 0 && totalBytes+int64(len(data)) > opts.MaxTotalBytes {
				break
			}
			member.Content = data
			member.Size = int64(len(data))
			member.ContentRead = true
			totalBytes += int64(len(data))
		}

		result.Members = append(result.Members, member)
	}

	return result, nil
}

func (execRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (execRunner) ListPaths(ctx context.Context, wimPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "wimlib-imagex", "dir", wimPath, "1")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("list wim contents: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("list wim contents: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "/" {
			continue
		}
		paths = append(paths, line)
	}
	return paths, nil
}

func (execRunner) ExtractFile(ctx context.Context, wimPath, memberPath string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "wimlib-imagex", "extract", wimPath, "1", memberPath, "--to-stdout")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("extract %s: %s", memberPath, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("extract %s: %w", memberPath, err)
	}
	return bytes.Clone(out), nil
}

func normalizeWIMPath(value string) string {
	return strings.ToLower(cleanWIMDisplayPath(value))
}

func cleanWIMDisplayPath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	if value == "" || value == "." || value == "/" {
		return ""
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if cleaned == "/" || cleaned == "." {
		return ""
	}
	return cleaned
}

func isTargetedPath(memberPath string) bool {
	switch memberPath {
	case "/windows/system32/config/sam",
		"/windows/system32/config/system",
		"/windows/system32/config/security",
		"/windows/ntds/ntds.dit":
		return true
	}
	base := strings.ToLower(path.Base(memberPath))
	if base == "bootstrap.ini" || base == "customsettings.ini" || base == "tasksequence.xml" {
		return true
	}
	return strings.HasPrefix(memberPath, "/windows/panther/") && strings.HasSuffix(memberPath, ".xml")
}

func shouldExtractContent(memberPath string) bool {
	switch strings.ToLower(path.Base(memberPath)) {
	case "bootstrap.ini", "customsettings.ini", "tasksequence.xml":
		return true
	}
	return strings.HasPrefix(memberPath, "/windows/panther/") && strings.HasSuffix(memberPath, ".xml")
}

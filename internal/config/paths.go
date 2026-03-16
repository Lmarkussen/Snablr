package config

import (
	"os"
	"path/filepath"
	"strings"
)

func applyPathContext(cfg *Config, resolvedConfigPath string) {
	cfg.configDir = ""
	if strings.TrimSpace(resolvedConfigPath) != "" {
		cfg.configDir = filepath.Dir(resolvedConfigPath)
	}
	cfg.runtimeRoot = detectRuntimeRoot(cfg.configDir)
}

func resolveConfigPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}

	candidates := []string{path}
	for _, base := range searchBaseDirs() {
		candidates = append(candidates, filepath.Join(base, path))
	}

	for _, candidate := range dedupePaths(candidates) {
		if !pathExists(candidate) {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err == nil {
			return abs
		}
		return filepath.Clean(candidate)
	}

	return path
}

func resolvePath(path string, bases ...string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	candidates := []string{path}
	for _, base := range bases {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		candidates = append(candidates, filepath.Join(base, path))
	}

	candidates = dedupePaths(candidates)
	for _, candidate := range candidates {
		if !pathExists(candidate) {
			continue
		}
		return filepath.Clean(candidate)
	}

	for _, base := range bases {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		return filepath.Clean(filepath.Join(base, path))
	}

	return filepath.Clean(path)
}

func detectRuntimeRoot(configDir string) string {
	candidates := make([]string, 0, 16)
	if strings.TrimSpace(configDir) != "" {
		candidates = append(candidates, ancestorDirs(configDir)...)
	}
	candidates = append(candidates, searchBaseDirs()...)

	for _, candidate := range dedupePaths(candidates) {
		if looksLikeRuntimeRoot(candidate) {
			return candidate
		}
	}

	if strings.TrimSpace(configDir) != "" {
		return filepath.Clean(configDir)
	}
	return ""
}

func searchBaseDirs() []string {
	bases := make([]string, 0, 16)
	if cwd, err := os.Getwd(); err == nil {
		bases = append(bases, ancestorDirs(cwd)...)
	}
	if exe, err := os.Executable(); err == nil {
		bases = append(bases, ancestorDirs(filepath.Dir(exe))...)
	}
	return dedupePaths(bases)
}

func ancestorDirs(start string) []string {
	start = strings.TrimSpace(start)
	if start == "" {
		return nil
	}

	current := filepath.Clean(start)
	out := []string{current}
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return out
		}
		out = append(out, parent)
		current = parent
	}
}

func looksLikeRuntimeRoot(path string) bool {
	return pathExists(filepath.Join(path, "configs", "rules", "default")) &&
		(pathExists(filepath.Join(path, "configs", "config.yaml")) || pathExists(filepath.Join(path, "go.mod")))
}

func dedupePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		cleaned := filepath.Clean(path)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		out = append(out, cleaned)
	}
	return out
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

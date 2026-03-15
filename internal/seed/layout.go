package seed

import (
	"fmt"
	"path"
	"strings"
)

func normalizeSeedPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.ReplaceAll(prefix, `\`, "/")
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return "SnablrLab"
	}
	return prefix
}

func joinSeedPath(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ReplaceAll(part, `\`, "/"))
		part = strings.Trim(part, "/")
		if part == "" {
			continue
		}
		clean = append(clean, part)
	}
	if len(clean) == 0 {
		return ""
	}
	return path.Clean(strings.Join(clean, "/"))
}

func buildFilename(prefix, format string, index int) string {
	ext := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(format)), ".")
	return fmt.Sprintf("%s_%03d.%s", prefix, index+1, ext)
}

func safeCleanPrefix(prefix string) (string, error) {
	normalized := normalizeSeedPrefix(prefix)
	if normalized == "" || normalized == "." {
		return "", fmt.Errorf("seed prefix must not be empty")
	}
	if normalized == ".." || strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "/../") {
		return "", fmt.Errorf("seed prefix must not contain parent directory traversal")
	}
	return normalized, nil
}

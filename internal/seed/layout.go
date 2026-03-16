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

func applyDepth(base string, depth int, index int, category string, persona string) string {
	if depth <= 0 {
		return joinSeedPath(base)
	}

	segments := []string{
		fmt.Sprintf("Tier-%02d", (index%5)+1),
		fmt.Sprintf("Batch-%02d", ((index/5)%6)+1),
		fmt.Sprintf("Review-%02d", ((index/3)%4)+1),
	}
	if strings.TrimSpace(category) != "" {
		segments = append(segments, strings.ToUpper(strings.ReplaceAll(category, "-", "_")))
	}
	if strings.TrimSpace(persona) != "" {
		segments = append(segments, strings.ToUpper(strings.ReplaceAll(persona, "-", "_")))
	}
	segments = append(segments, "Archive", "Working", "Staged")

	out := []string{base}
	for i := 0; i < depth; i++ {
		out = append(out, segments[i%len(segments)])
	}
	return joinSeedPath(out...)
}

func displayName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}
	return strings.Join(parts, " ")
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

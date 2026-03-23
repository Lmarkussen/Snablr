package sqliteinspect

import (
	"math"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

var sqliteCandidateExtensions = map[string]struct{}{
	".sqlite":  {},
	".sqlite3": {},
	".db":      {},
	".db3":     {},
}

var interestingTableTokens = []string{
	"user", "account", "credential", "secret", "token", "session", "config", "setting",
}

var interestingColumnTokens = []string{
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "connection_string", "connstr", "dsn", "db_url", "database_url",
}

var contextColumnTokens = []string{
	"user", "username", "email", "account", "name",
}

var weakValueBases = []string{
	"changeme", "default", "demo", "dummy", "example", "fake", "letmein", "password", "placeholder", "qwerty", "sample", "secret", "test", "token", "welcome",
}

func normalizedExtension(ext string) string {
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.ToLower(ext)
}

func isSQLiteCandidateExtension(ext string) bool {
	_, ok := sqliteCandidateExtensions[normalizedExtension(ext)]
	return ok
}

func hasSQLiteHeader(content []byte) bool {
	return len(content) >= 16 && string(content[:16]) == "SQLite format 3\x00"
}

func tablePriority(name string) int {
	lower := strings.ToLower(strings.TrimSpace(name))
	score := 0
	for _, token := range interestingTableTokens {
		if strings.Contains(lower, token) {
			score += 3
		}
	}
	if score == 0 && strings.HasPrefix(lower, "sqlite_") {
		return -1
	}
	return score
}

func columnPriority(name string) int {
	lower := strings.ToLower(strings.TrimSpace(name))
	score := 0
	for _, token := range interestingColumnTokens {
		if strings.Contains(lower, token) {
			score += 4
		}
	}
	return score
}

func isContextColumn(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, token := range contextColumnTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func compositePath(filePath, table, column string) string {
	location := strings.TrimSpace(table)
	if strings.TrimSpace(column) != "" {
		location += "." + strings.TrimSpace(column)
	}
	if location == "" {
		return filePath
	}
	return strings.TrimSpace(filePath) + "::" + location
}

func baseFilePath(path string) string {
	if idx := strings.Index(path, "::"); idx >= 0 {
		return path[:idx]
	}
	return path
}

func trimValue(value string, max int64) string {
	value = strings.TrimSpace(value)
	if max <= 0 || int64(len(value)) <= max {
		return value
	}
	return strings.TrimSpace(value[:max])
}

type valueQuality struct {
	Score  int
	Label  string
	Reason string
	Weak   bool
	Strong bool
}

func assessSensitiveValueQuality(value string) valueQuality {
	trimmed := strings.TrimSpace(strings.Trim(value, `"'`))
	if trimmed == "" {
		return valueQuality{Label: "low", Reason: "value was empty after trimming", Weak: true}
	}
	if isPlaceholderValue(trimmed) || isCommonWeakValue(trimmed) {
		return valueQuality{Score: 1, Label: "low", Reason: "value looks like a placeholder or common sample credential", Weak: true}
	}
	if len(trimmed) < 8 {
		return valueQuality{Score: 2, Label: "low", Reason: "value is shorter than a plausible credential or secret", Weak: true}
	}

	entropy := shannonEntropy(trimmed)
	classes := characterClassCount(trimmed)
	unique := uniqueRuneCount(trimmed)
	if unique <= 2 {
		return valueQuality{Score: 2, Label: "low", Reason: "value has too little variation to look usable", Weak: true}
	}
	if entropy < 1.8 || (entropy < 2.4 && classes < 2) {
		return valueQuality{Score: 3, Label: "low", Reason: "value has low entropy and limited character diversity", Weak: true}
	}

	switch {
	case len(trimmed) >= 14 && unique >= 6 && (classes >= 3 || entropy >= 3.2):
		return valueQuality{Score: 18, Label: "high", Reason: "value is long and has strong entropy or character diversity", Strong: true}
	case len(trimmed) >= 10 && unique >= 5 && (classes >= 2 || entropy >= 2.7):
		return valueQuality{Score: 12, Label: "medium", Reason: "value has plausible length and diversity for a real credential or secret"}
	default:
		return valueQuality{Score: 8, Label: "medium", Reason: "value looks plausible, but only has moderate strength indicators"}
	}
}

func isPlaceholderValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	switch {
	case value == "":
		return true
	case strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"):
		return true
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		return true
	case strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}"):
		return true
	}
	switch value {
	case "password", "secret", "token", "username", "server", "database":
		return true
	}
	for _, token := range []string{"changeme", "placeholder", "replace_me", "replace-me", "example", "sample", "test"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func isCommonWeakValue(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if normalized == "" {
		return true
	}
	collapsed := collapseAlphaNum(normalized)
	if collapsed == "" {
		return true
	}
	for _, base := range weakValueBases {
		if collapsed == base {
			return true
		}
		if strings.HasPrefix(collapsed, base) && digitsOnly(strings.TrimPrefix(collapsed, base)) {
			return true
		}
	}
	return false
}

func collapseAlphaNum(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(unicode.ToLower(r))
		}
	}
	return builder.String()
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func characterClassCount(value string) int {
	var lower, upper, digit, special bool
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			special = true
		}
	}
	count := 0
	for _, present := range []bool{lower, upper, digit, special} {
		if present {
			count++
		}
	}
	return count
}

func uniqueRuneCount(value string) int {
	seen := make(map[rune]struct{})
	for _, r := range value {
		seen[r] = struct{}{}
	}
	return len(seen)
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range value {
		counts[r]++
	}
	total := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range counts {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

type namedScore struct {
	Name  string
	Score int
}

func sortNamedScores(items []namedScore) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score == items[j].Score {
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		}
		return items[i].Score > items[j].Score
	})
}

func fileBase(path string) string {
	return filepath.Base(baseFilePath(path))
}

package dbinspect

import (
	"path/filepath"
	"sort"
	"strings"
)

func candidateFragments(line string) []string {
	var fragments []string
	seen := make(map[string]struct{})
	add := func(value string) {
		value = trimWrapper(value)
		if len(value) < 8 {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		fragments = append(fragments, value)
	}

	add(line)
	if key, value, ok := splitKeyValue(line); ok {
		if looksLikeConnectionLabel(key) {
			add(value)
		}
	}
	for _, match := range quotedValueRegex.FindAllStringSubmatch(line, -1) {
		for _, value := range match[1:] {
			if strings.TrimSpace(value) != "" {
				add(value)
			}
		}
	}
	return fragments
}

func splitKeyValue(line string) (string, string, bool) {
	if idx := strings.Index(line, "="); idx > 0 && idx < len(line)-1 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
	}
	if idx := strings.Index(line, ":"); idx > 0 && idx < len(line)-1 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
	}
	return "", "", false
}

func looksLikeConnectionLabel(label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	return strings.Contains(label, "connection") ||
		strings.Contains(label, "datasource") ||
		strings.Contains(label, "dsn") ||
		strings.Contains(label, "jdbc")
}

func parseSemicolonKV(value string) (map[string]string, int) {
	values := make(map[string]string)
	count := 0
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, rawValue, ok := splitKeyValue(part)
		if !ok {
			continue
		}
		values[normalizeKVKey(key)] = trimWrapper(rawValue)
		count++
	}
	return values, count
}

func normalizeKVKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, " ", "")
	switch key {
	case "userid":
		return "userid"
	case "uid":
		return "uid"
	case "user":
		return "user"
	case "username":
		return "username"
	case "pwd":
		return "pwd"
	case "password":
		return "password"
	case "datasource", "datasourcepath", "addr", "address", "networkaddress", "dbq":
		return "datasource"
	case "initialcatalog", "databasename":
		return "database"
	case "dbname":
		return "dbname"
	case "trustedconnection":
		return "trustedconnection"
	case "integratedsecurity":
		return "integratedsecurity"
	case "servicename":
		return "servicename"
	default:
		return key
	}
}

func authSummary(values map[string]string) authFields {
	user := meaningfulValue(firstNonEmpty(values["uid"], values["userid"], values["user"], values["username"]))
	password := meaningfulValue(firstNonEmpty(values["password"], values["pwd"]))
	integrated := isTruthy(firstNonEmpty(values["integratedsecurity"], values["trustedconnection"]))
	return authFields{
		user:       user,
		password:   password,
		integrated: integrated,
	}
}

func detectEcosystem(values map[string]string) string {
	joined := strings.ToLower(strings.Join(sortedValues(values), ";"))
	switch {
	case strings.Contains(joined, "sqlserver"), strings.Contains(joined, "sqloledb"), strings.Contains(joined, "mssql"), strings.Contains(joined, "initialcatalog"):
		return "mssql"
	case strings.Contains(joined, "mysql"), strings.Contains(joined, ":3306"), strings.Contains(joined, "jdbc:mysql"):
		return "mysql"
	case strings.Contains(joined, "postgres"), strings.Contains(joined, "pgsql"), strings.Contains(joined, ":5432"), strings.Contains(joined, "jdbc:postgresql"):
		return "postgresql"
	case strings.Contains(joined, "oracle"), strings.Contains(joined, "oraoledb"), strings.Contains(joined, ":1521"), strings.Contains(joined, "servicename"), strings.Contains(joined, "sid"):
		return "oracle"
	case strings.Contains(joined, ".sqlite"), strings.Contains(joined, ".sqlite3"), strings.Contains(joined, "jdbc:sqlite"), strings.Contains(joined, "sqlite"):
		return "sqlite"
	case strings.Contains(joined, ".accdb"), strings.Contains(joined, ".mdb"), strings.Contains(joined, "microsoft.ace.oledb"), strings.Contains(joined, "microsoft.jet.oledb"):
		return "access"
	case strings.Contains(joined, "dsn="), strings.Contains(joined, "driver="), strings.Contains(joined, "odbc"):
		return "odbc"
	default:
		return ""
	}
}

func ecosystemOrFallback(ecosystem string, values map[string]string) string {
	if ecosystem != "" {
		return ecosystem
	}
	if driver := strings.TrimSpace(values["driver"]); driver != "" {
		return "odbc"
	}
	return "generic"
}

func summarizeConnection(values map[string]string) string {
	endpoint := meaningfulValue(firstNonEmpty(values["server"], values["host"], values["datasource"], values["dsn"]))
	database := meaningfulValue(firstNonEmpty(values["database"], values["dbname"], values["initialcatalog"], values["servicename"], values["sid"]))
	driver := meaningfulValue(firstNonEmpty(values["driver"], values["provider"]))

	var parts []string
	if driver != "" {
		parts = append(parts, strings.TrimSpace(driver))
	}
	if endpoint != "" {
		parts = append(parts, strings.TrimSpace(endpoint))
	}
	if database != "" {
		parts = append(parts, strings.TrimSpace(database))
	}
	if len(parts) == 0 {
		return "validated database connection details"
	}
	return strings.Join(parts, " -> ")
}

func summarizeKV(values map[string]string) string {
	pairs := make([]string, 0, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		pairs = append(pairs, key+"="+values[key])
	}
	return strings.Join(pairs, ";")
}

func sortedValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	return out
}

func normalizedPath(candidate Candidate) string {
	return filepath.ToSlash(strings.TrimSpace(candidate.FilePath))
}

func normalizedName(candidate Candidate) string {
	name := strings.TrimSpace(candidate.Name)
	if name == "" {
		name = filepath.Base(candidate.FilePath)
	}
	return strings.ToLower(name)
}

func normalizedExtension(candidate Candidate) string {
	ext := strings.TrimSpace(candidate.Extension)
	if ext == "" {
		ext = filepath.Ext(candidate.Name)
	}
	if ext == "" {
		ext = filepath.Ext(candidate.FilePath)
	}
	if ext == "" {
		return ""
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return strings.ToLower(ext)
}

func normalizedContent(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	text := strings.TrimPrefix(string(content), "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return text
}

func trimWrapper(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return strings.TrimSpace(value)
}

func firstSubmatch(rx interface{ FindStringSubmatch(string) []string }, value string) string {
	matches := rx.FindStringSubmatch(value)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func meaningfulValue(value string) string {
	value = trimWrapper(value)
	if isPlaceholderValue(value) {
		return ""
	}
	return value
}

func isPlaceholderValue(value string) bool {
	value = strings.ToLower(trimWrapper(value))
	switch {
	case value == "":
		return false
	case strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"):
		return true
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		return true
	case strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}"):
		return true
	}
	switch value {
	case "username", "user", "password", "pwd", "server", "host", "database", "dbname", "dsn":
		return true
	}
	for _, token := range placeholderTokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "sspi":
		return true
	default:
		return false
	}
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

func flatten(value string, limit int) string {
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", "")
	return limitRunes(value, limit)
}

func limitRunes(value string, maxCount int) string {
	if maxCount <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= maxCount {
		return value
	}
	return string(runes[:maxCount]) + "..."
}

func redactText(value string) string {
	return passwordKVRegex.ReplaceAllString(value, `${1}=********`)
}

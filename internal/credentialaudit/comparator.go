// Package credentialaudit contains offline-only benchmark comparison logic.
// It is intentionally not imported by the scanner or Findings Engine.
package credentialaudit

import (
	"net/url"
	"regexp"
	"strings"
)

type ExpectedPair struct {
	ID, SourcePath, Username, Password, Split string
}

type ObservedMaterial struct {
	RowID, SourcePath, MaterialType, Identity, Value, Verification string
}

type Pair struct{ Username, Password string }

type Match struct {
	ExpectedID string
	ObservedID string
	Basis      string
}

type Report struct {
	Matches        []Match
	MissingIDs     []string
	UniqueExpected int
	UniqueMatched  int
}

// NormalizeSourcePath preserves archive-member identity while allowing a
// manifest's base path to match a persisted path that includes !member.
func NormalizeSourcePath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), `\`, "/")
	return strings.TrimSuffix(path, "/")
}

func BaseSourcePath(path string) string {
	path = NormalizeSourcePath(path)
	if index := strings.IndexByte(path, '!'); index >= 0 {
		return path[:index]
	}
	return path
}

// ExtractPairs returns only explicit pairs from password rows and supported
// connection-string rows. It never treats a connection string itself as a
// plaintext username/password pair.
func ExtractPairs(material ObservedMaterial) []Pair {
	if strings.EqualFold(material.MaterialType, "password") && material.Identity != "" && material.Value != "" {
		return []Pair{{Username: material.Identity, Password: material.Value}}
	}
	if !strings.EqualFold(material.MaterialType, "connection_string") && !strings.EqualFold(material.MaterialType, "dsn") {
		return nil
	}
	value := material.Value
	result := make([]Pair, 0, 1)
	if parsed, ok := parseURI(value); ok {
		result = append(result, parsed)
	}
	username := connectionField(value, "user id", "uid", "username", "user", "login", "account", "brukernavn", "bruker", "brukerkonto", "påloggingsnavn")
	password := connectionField(value, "password", "pwd", "passwd", "secret", "passord")
	if username == "" || password == "" {
		username = firstNonEmpty(username, connectionKeywordField(value, "user", "username", "userid", "uid", "brukernavn", "bruker", "brukerkonto", "påloggingsnavn"))
		password = firstNonEmpty(password, connectionKeywordField(value, "password", "pwd", "passord"))
	}
	if username != "" && password != "" {
		result = appendUnique(result, Pair{Username: username, Password: password})
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func connectionKeywordField(value string, names ...string) string {
	for _, field := range splitKeywordFields(value) {
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		for _, name := range names {
			if key != name {
				continue
			}
			raw = strings.TrimSpace(raw)
			if len(raw) >= 2 && ((raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"')) {
				raw = raw[1 : len(raw)-1]
			}
			if !looksUnsafe(raw) {
				return raw
			}
		}
	}
	return ""
}

func splitKeywordFields(value string) []string {
	fields := make([]string, 0, 8)
	start := 0
	var quote byte
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == ' ' || character == '\t' || character == '\r' || character == '\n' {
			if start < index {
				fields = append(fields, value[start:index])
			}
			start = index + 1
		}
	}
	if start < len(value) {
		fields = append(fields, value[start:])
	}
	return fields
}

func Compare(expected []ExpectedPair, observed []ObservedMaterial) Report {
	byPath := make(map[string][]ExpectedPair)
	unique := make(map[Pair]struct{})
	for _, item := range expected {
		byPath[BaseSourcePath(item.SourcePath)] = append(byPath[BaseSourcePath(item.SourcePath)], item)
		unique[Pair{Username: item.Username, Password: item.Password}] = struct{}{}
	}
	report := Report{UniqueExpected: len(unique)}
	matchedIDs := make(map[string]struct{})
	matchedPairs := make(map[Pair]struct{})
	for _, item := range observed {
		for _, pair := range ExtractPairs(item) {
			for _, want := range byPath[BaseSourcePath(item.SourcePath)] {
				if pair.Username != want.Username || pair.Password != want.Password {
					continue
				}
				if _, exists := matchedIDs[want.ID]; exists {
					continue
				}
				matchedIDs[want.ID] = struct{}{}
				matchedPairs[pair] = struct{}{}
				basis := "explicit password row"
				if strings.EqualFold(item.MaterialType, "connection_string") || strings.EqualFold(item.MaterialType, "dsn") {
					basis = "explicit connection-string fields"
				}
				report.Matches = append(report.Matches, Match{ExpectedID: want.ID, ObservedID: item.RowID, Basis: basis})
			}
		}
	}
	for _, item := range expected {
		if _, ok := matchedIDs[item.ID]; !ok {
			report.MissingIDs = append(report.MissingIDs, item.ID)
		}
	}
	report.UniqueMatched = len(matchedPairs)
	return report
}

func parseURI(value string) (Pair, bool) {
	if !strings.Contains(strings.ToLower(value), "://") {
		return Pair{}, false
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(trimmed), "jdbc:") {
		trimmed = trimmed[len("jdbc:"):]
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.User == nil {
		if err != nil {
			return Pair{}, false
		}
		query := parsed.Query()
		username := firstNonEmpty(query.Get("user"), query.Get("username"), query.Get("uid"))
		password := firstNonEmpty(query.Get("password"), query.Get("pwd"), query.Get("pass"))
		if username == "" || password == "" || looksUnsafe(username) || looksUnsafe(password) {
			return Pair{}, false
		}
		return Pair{Username: username, Password: password}, true
	}
	password, hasPassword := parsed.User.Password()
	username := parsed.User.Username()
	if username == "" || !hasPassword || password == "" || looksUnsafe(password) {
		return Pair{}, false
	}
	return Pair{Username: username, Password: password}, true
}

func connectionField(value string, names ...string) string {
	for _, field := range splitFields(value) {
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		for _, name := range names {
			if key != name {
				continue
			}
			value := strings.TrimSpace(raw)
			if len(value) >= 2 && value[0] == '{' && value[len(value)-1] == '}' {
				value = strings.ReplaceAll(value[1:len(value)-1], "}}", "}")
			}
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			if looksUnsafe(value) {
				return ""
			}
			return value
		}
	}
	return ""
}

func splitFields(value string) []string {
	fields := make([]string, 0, 8)
	start := 0
	braceDepth := 0
	var quote byte
	for index := 0; index < len(value); index++ {
		character := value[index]
		if quote != 0 {
			if character == quote {
				if index+1 < len(value) && value[index+1] == quote {
					index++
					continue
				}
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case ';':
			if braceDepth == 0 {
				fields = append(fields, value[start:index])
				start = index + 1
			}
		}
	}
	return append(fields, value[start:])
}

var unsafeValue = regexp.MustCompile(`(?i)\$\{|change[_-]?me|\*{3,}|encrypted|ciphertext|opaque`)

func looksUnsafe(value string) bool {
	return strings.TrimSpace(value) == "" || unsafeValue.MatchString(value)
}

func appendUnique(values []Pair, value Pair) []Pair {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

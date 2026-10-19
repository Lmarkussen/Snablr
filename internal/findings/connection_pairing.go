package findings

import (
	"net/url"
	"strings"

	"snablr/internal/credentialanalysis"
)

type connectionPair struct {
	Username string
	Password string
	Provider string
	Server   string
	Port     string
	Database string
}

type connectionField struct {
	Key   string
	Value string
}

func deriveConnectionPair(candidate credentialanalysis.Candidate) (connectionPair, bool) {
	typ := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	if typ != "connection_string" && typ != "dsn" {
		return connectionPair{}, false
	}
	value := strings.TrimSpace(candidate.Value)
	if value == "" || isOpaqueCredential(candidate) || looksLikePlaceholder(value) {
		return connectionPair{}, false
	}
	if pair, ok := parseDatabaseURI(value); ok {
		return pair, true
	}
	if pair, ok := parseDelimitedConnection(value); ok {
		return pair, true
	}
	return parseKeywordConnection(value)
}

func parseDatabaseURI(value string) (connectionPair, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return connectionPair{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "postgres", "postgresql", "mysql", "mariadb", "sqlserver":
	default:
		return connectionPair{}, false
	}
	password, hasPassword := parsed.User.Password()
	username := parsed.User.Username()
	if !hasPassword || invalidConnectionValue(username) || invalidConnectionValue(password) {
		return connectionPair{}, false
	}
	database := strings.TrimPrefix(parsed.Path, "/")
	return connectionPair{
		Username: username,
		Password: password,
		Provider: scheme,
		Server:   parsed.Hostname(),
		Port:     parsed.Port(),
		Database: database,
	}, true
}

func parseDelimitedConnection(value string) (connectionPair, bool) {
	fields := splitConnectionFields(value)
	var pair connectionPair
	var usernames, passwords []string
	for _, field := range fields {
		key := strings.ToLower(strings.TrimSpace(field.Key))
		fieldValue := strings.TrimSpace(field.Value)
		if fieldValue == "" {
			continue
		}
		switch key {
		case "user id", "uid", "username", "user":
			usernames = appendUniqueString(usernames, fieldValue)
		case "password", "pwd":
			passwords = appendUniqueString(passwords, fieldValue)
		case "provider", "provider name", "driver":
			pair.Provider = fieldValue
		case "server", "data source", "address", "addr", "host":
			pair.Server = fieldValue
		case "port":
			pair.Port = fieldValue
		case "initial catalog", "database", "catalog":
			pair.Database = fieldValue
		case "integrated security", "trusted_connection", "trusted connection":
			if strings.EqualFold(fieldValue, "true") || strings.EqualFold(fieldValue, "yes") {
				return connectionPair{}, false
			}
		}
	}
	if len(usernames) != 1 || len(passwords) != 1 || invalidConnectionValue(usernames[0]) || invalidConnectionValue(passwords[0]) {
		return connectionPair{}, false
	}
	pair.Username = usernames[0]
	pair.Password = passwords[0]
	return pair, true
}

func parseKeywordConnection(value string) (connectionPair, bool) {
	fields := splitKeywordFields(value)
	if len(fields) < 2 {
		return connectionPair{}, false
	}
	var pair connectionPair
	var username, password string
	for index := 0; index < len(fields); index++ {
		key, fieldValue, ok := strings.Cut(fields[index], "=")
		if !ok {
			return connectionPair{}, false
		}
		fieldValue = strings.Trim(fieldValue, `"'`)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "user", "username", "userid", "uid":
			username = fieldValue
		case "password", "pwd":
			password = fieldValue
		case "host", "server":
			pair.Server = fieldValue
		case "dbname", "database":
			pair.Database = fieldValue
		}
	}
	if invalidConnectionValue(username) || invalidConnectionValue(password) {
		return connectionPair{}, false
	}
	pair.Username = username
	pair.Password = password
	pair.Provider = "postgresql"
	return pair, true
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

func splitConnectionFields(value string) []connectionField {
	var fields []connectionField
	start := 0
	quote := rune(0)
	braceDepth := 0
	for index, character := range value {
		switch {
		case quote != 0:
			if character == quote {
				quote = 0
			}
		case character == '\'' || character == '"':
			quote = character
		case character == '{':
			braceDepth++
		case character == '}' && braceDepth > 0:
			braceDepth--
		case character == ';' && braceDepth == 0:
			appendConnectionField(&fields, value[start:index])
			start = index + 1
		}
	}
	appendConnectionField(&fields, value[start:])
	return fields
}

func appendConnectionField(fields *[]connectionField, raw string) {
	key, fieldValue, ok := strings.Cut(raw, "=")
	if !ok {
		return
	}
	fieldValue = strings.TrimSpace(fieldValue)
	if len(fieldValue) >= 2 {
		if (fieldValue[0] == '\'' && fieldValue[len(fieldValue)-1] == '\'') || (fieldValue[0] == '"' && fieldValue[len(fieldValue)-1] == '"') {
			fieldValue = fieldValue[1 : len(fieldValue)-1]
		} else if fieldValue[0] == '{' && fieldValue[len(fieldValue)-1] == '}' {
			fieldValue = strings.ReplaceAll(fieldValue[1:len(fieldValue)-1], "}}", "}")
		}
	}
	*fields = append(*fields, connectionField{Key: key, Value: fieldValue})
}

func invalidConnectionValue(value string) bool {
	return strings.TrimSpace(value) == "" || looksLikePlaceholder(value)
}

func looksLikePlaceholder(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || strings.Contains(value, "${") || strings.Contains(value, "%{") {
		return true
	}
	for _, marker := range []string{"change_me", "changeme", "example-password", "password_here", "not-a-password", "********", "encrypted", "ciphertext", "opaque", "dpapi"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func connectionPairOrigin(candidate credentialanalysis.Candidate) string {
	pair, ok := deriveConnectionPair(candidate)
	if !ok {
		return "Connection String Credential"
	}
	if strings.EqualFold(pair.Provider, "sqloledb") || strings.Contains(strings.ToLower(pair.Provider), "sql") {
		return "MSSQL / Database Credential"
	}
	return "Database Credential"
}

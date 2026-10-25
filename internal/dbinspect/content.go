package dbinspect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const sqliteHeader = "SQLite format 3\x00"

func inspectSQLiteArtifact(candidate Candidate, content []byte, seen map[string]struct{}) []Match {
	if len(content) < 100 || !bytes.Equal(content[:len(sqliteHeader)], []byte(sqliteHeader)) {
		return nil
	}

	pageSize := int(binary.BigEndian.Uint16(content[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 32768 && pageSize != 65536 || pageSize&(pageSize-1) != 0 {
		return nil
	}
	if content[18] < 1 || content[18] > 2 || content[19] < 1 || content[19] > 2 {
		return nil
	}
	if int(content[20]) >= int(pageSize) || content[21] != 64 || content[22] != 32 || content[23] != 32 {
		return nil
	}
	if binary.BigEndian.Uint32(content[28:32]) == 0 || int64(len(content)) < int64(pageSize) {
		return nil
	}

	const id = "dbinspect.artifact.sqlite_structural"
	if _, exists := seen[id]; exists {
		return nil
	}
	seen[id] = struct{}{}
	return []Match{{
		ID:                  id,
		Name:                "Structurally Validated SQLite Database Artifact",
		Description:         "The file contains a bounded, structurally valid SQLite database header.",
		RuleType:            "content",
		SignalType:          "validated",
		Severity:            "high",
		Confidence:          "high",
		Category:            "database-artifacts",
		Match:               sqliteHeader,
		MatchedText:         sqliteHeader,
		MatchedTextRedacted: sqliteHeader,
		Snippet:             sqliteHeader,
		Context:             candidate.FilePath,
		ContextRedacted:     candidate.FilePath,
		Explanation:         "SQLite header fields, page-size constraints, format versions, payload fractions, and minimum page length passed bounded structural validation without opening the source file.",
		Remediation:         "Review the database artifact location and restrict access according to its contents and intended use.",
		Tags:                []string{"database", "db:source:local-artifact", "db:type:sqlite", "db:status:confirmed"},
	}}
}

func inspectStructuredDatabaseConfig(candidate Candidate, raw []byte, text string, seen map[string]struct{}) []Match {
	if ext := normalizedExtension(candidate); ext == ".ini" || ext == ".dsn" || ext == ".udl" || ext == ".ora" {
		return nil
	}
	for key := range seen {
		if strings.HasPrefix(key, "dbinspect.infrastructure.dsn::") || strings.HasPrefix(key, "dbinspect.infrastructure.connection_string::") {
			return nil
		}
	}
	context := strings.ToLower(text)
	if !hasDatabaseStructuredContext(context) {
		return nil
	}
	var matches []Match
	for index, fields := range structuredDatabaseGroups(text) {
		endpoint := firstNonEmpty(fields["server"], fields["host"], fields["hostname"], fields["datasource"])
		database := firstNonEmpty(fields["database"], fields["dbname"], fields["catalog"], fields["service"], fields["name"])
		provider := firstNonEmpty(fields["provider"], fields["driver"], fields["engine"])
		port := fields["port"]
		instance := fields["instance"]
		if endpoint == "" || database == "" {
			continue
		}

		key := fmt.Sprintf("dbinspect.infrastructure.structured_config::%d::%s", index, strings.ToLower(strings.Join([]string{provider, endpoint, port, instance, database}, "|")))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, Match{
			ID:                  "dbinspect.infrastructure.structured_config",
			Name:                "Validated Database Configuration Endpoint",
			Description:         "A database endpoint and database name were parsed from structured configuration content.",
			RuleType:            "content",
			SignalType:          "validated",
			Severity:            "medium",
			Confidence:          "high",
			Category:            "database-infrastructure",
			Match:               summarizeStructuredFields(fields),
			MatchedText:         string(raw),
			MatchedTextRedacted: string(raw),
			Snippet:             string(raw),
			Context:             string(raw),
			ContextRedacted:     string(raw),
			ObservationID:       fmt.Sprintf("structured:%d:%s", index, strings.ToLower(summarizeStructuredFields(fields))),
			Explanation:         "This finding is based on endpoint and database fields in structured configuration; it does not assert reachability or authentication success.",
			Remediation:         "Review the configured database endpoint and protect any associated credentials or configuration file.",
			Tags:                []string{"database", "db:source:config", "db:type:configured-endpoint", "db:status:configured"},
		})
	}
	return matches
}

func structuredDatabaseGroups(text string) []map[string]string {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var document interface{}
		if json.Unmarshal([]byte(text), &document) == nil {
			groups := jsonDatabaseGroups(document)
			if len(groups) > 0 {
				return groups
			}
		}
	}

	if strings.Contains(trimmed, "<") && strings.Contains(trimmed, ">") {
		groups := make([]map[string]string, 0)
		for _, tag := range structuredDatabaseTagRegex.FindAllString(text, -1) {
			fields := fieldsFromStructuredText(tag)
			if len(fields) > 0 {
				groups = append(groups, fields)
			}
		}
		if len(groups) > 0 {
			return groups
		}
	}

	return lineDatabaseGroups(text)
}

func jsonDatabaseGroups(value interface{}) []map[string]string {
	object, ok := value.(map[string]interface{})
	if !ok {
		if list, ok := value.([]interface{}); ok {
			var groups []map[string]string
			for _, item := range list {
				groups = append(groups, jsonDatabaseGroups(item)...)
			}
			return groups
		}
		return nil
	}

	fields := make(map[string]string)
	var nested []map[string]string
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := object[key]
		normalized := normalizeStructuredField(key)
		if normalized != "" {
			if scalar, ok := value.(string); ok {
				fields[normalized] = strings.TrimSpace(scalar)
			} else if number, ok := value.(float64); ok {
				fields[normalized] = formatStructuredNumber(number)
			}
		}
		if _, isObject := value.(map[string]interface{}); isObject {
			nested = append(nested, jsonDatabaseGroups(value)...)
		}
		if _, isList := value.([]interface{}); isList {
			nested = append(nested, jsonDatabaseGroups(value)...)
		}
	}
	if len(fields) > 0 {
		nested = append([]map[string]string{fields}, nested...)
	}
	return nested
}

func lineDatabaseGroups(text string) []map[string]string {
	groupByScope := make(map[string]map[string]string)
	var order []string
	section := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		match := structuredDatabaseFieldRegex.FindStringSubmatch(trimmed)
		if len(match) < 5 {
			continue
		}
		key := normalizeStructuredField(match[1])
		value := strings.TrimSpace(firstNonEmpty(match[2], match[3], match[4]))
		if key == "" || value == "" || value == "{" {
			continue
		}
		scope := structuredFieldScope(match[1], key, section)
		if _, exists := groupByScope[scope]; !exists {
			groupByScope[scope] = make(map[string]string)
			order = append(order, scope)
		}
		groupByScope[scope][key] = value
	}
	groups := make([]map[string]string, 0, len(order))
	for _, scope := range order {
		groups = append(groups, groupByScope[scope])
	}
	return groups
}

func structuredFieldScope(rawKey, normalized, section string) string {
	key := strings.ToLower(strings.TrimSpace(rawKey))
	key = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(key)
	for _, suffix := range []string{"_db_host", "_db_name"} {
		if strings.HasSuffix(key, suffix) {
			return strings.TrimSuffix(key, suffix)
		}
	}
	if strings.HasSuffix(key, "_"+normalized) {
		return strings.TrimSuffix(key, "_"+normalized)
	}
	if key == normalized {
		if section != "" {
			return strings.ToLower(section)
		}
		return "_default"
	}
	return key
}

func fieldsFromStructuredText(text string) map[string]string {
	fields := make(map[string]string)
	for _, match := range structuredDatabaseFieldRegex.FindAllStringSubmatch(text, -1) {
		if len(match) < 5 {
			continue
		}
		key := normalizeStructuredField(match[1])
		value := strings.TrimSpace(firstNonEmpty(match[2], match[3], match[4]))
		if key != "" && value != "" && value != "{" {
			fields[key] = value
		}
	}
	return fields
}

func formatStructuredNumber(value float64) string {
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.6f", value), "0"), ".")
}

func normalizeStructuredField(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(key)
	if key == "db_name" || strings.HasSuffix(key, "_db_name") {
		return "database"
	}
	for _, suffix := range []string{"server", "host", "hostname", "datasource", "database", "dbname", "db_name", "catalog", "service", "service_name", "instance", "port", "provider", "driver", "engine", "authentication", "integrated_security", "username", "user", "uid", "password", "pwd", "name"} {
		if key == suffix || strings.HasSuffix(key, "_"+suffix) {
			return suffix
		}
	}
	return ""
}

func hasDatabaseStructuredContext(text string) bool {
	for _, token := range []string{"database", "datasource", "connection", "jdbc", "dsn", "db_", "db."} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func summarizeStructuredFields(fields map[string]string) string {
	ordered := []string{"provider", "server", "host", "port", "instance", "database", "dbname", "catalog", "service", "authentication"}
	parts := make([]string, 0, len(ordered))
	seen := make(map[string]struct{})
	for _, key := range ordered {
		if value := strings.TrimSpace(fields[key]); value != "" {
			parts = append(parts, key+"="+value)
			seen[key] = struct{}{}
		}
	}
	if _, exists := seen["database"]; !exists {
		if value := strings.TrimSpace(fields["name"]); value != "" {
			parts = append(parts, "database="+value)
		}
	}
	return strings.Join(parts, ";")
}

func inspectOracleTNS(candidate Candidate, text string, seen map[string]struct{}) []Match {
	name := normalizedName(candidate)
	if name != "tnsnames.ora" && !strings.Contains(strings.ToUpper(text), "(DESCRIPTION=") {
		return nil
	}

	aliases := tnsAliasRegex.FindAllStringSubmatchIndex(text, -1)
	if len(aliases) == 0 {
		return nil
	}

	var matches []Match
	for idx, aliasIdx := range aliases {
		alias := strings.TrimSpace(text[aliasIdx[2]:aliasIdx[3]])
		blockStart := aliasIdx[0]
		blockEnd := len(text)
		if idx+1 < len(aliases) {
			blockEnd = aliases[idx+1][0]
		}
		block := text[blockStart:blockEnd]

		host := meaningfulValue(firstSubmatch(tnsHostRegex, block))
		service := meaningfulValue(firstSubmatch(tnsServiceRegex, block))
		if service == "" {
			service = meaningfulValue(firstSubmatch(tnsSIDRegex, block))
		}
		port := meaningfulValue(firstSubmatch(tnsPortRegex, block))
		if alias == "" || host == "" || service == "" {
			continue
		}

		lineNumber := 1 + strings.Count(text[:blockStart], "\n")
		matchText := alias + " -> " + host
		if port != "" {
			matchText += ":" + port
		}
		matchText += "/" + service

		key := "dbinspect.infrastructure.oracle_tns::" + strings.ToLower(matchText)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		matches = append(matches, Match{
			ID:                  "dbinspect.infrastructure.oracle_tns",
			Name:                "Validated Oracle TNS Service Indicator",
			Description:         "Validated Oracle Net service details were parsed from a TNS configuration file.",
			RuleType:            "content",
			SignalType:          "validated",
			Severity:            "medium",
			Confidence:          "high",
			Category:            "database-infrastructure",
			Match:               matchText,
			MatchedText:         block,
			MatchedTextRedacted: block,
			Snippet:             flatten(block, 160),
			Context:             limitRunes(strings.TrimSpace(block), 320),
			ContextRedacted:     limitRunes(strings.TrimSpace(block), 320),
			LineNumber:          lineNumber,
			Explanation:         "This finding comes from structured Oracle Net configuration, not a broad keyword match.",
			Remediation:         "Review whether this Oracle service definition should be present in the share and restrict access to database network configuration files.",
			Tags: []string{
				"database",
				"db:source:config",
				"db:type:server-indicator",
				"db:ecosystem:oracle",
			},
		})
	}

	return matches
}

func inspectINISections(text string, seen map[string]struct{}) []Match {
	lines := strings.Split(text, "\n")
	currentSection := ""
	currentLines := make([]string, 0)
	currentValues := make(map[string]string)
	var matches []Match

	flush := func() {
		if currentSection == "" {
			return
		}
		if observation, ok := inspectINISection(currentSection, currentValues); ok {
			key := observation.id + "::" + strings.ToLower(observation.match)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				matches = append(matches, matchFromObservation(observation, strings.Join(currentLines, "\n")))
			}
		}
		currentSection = ""
		currentLines = currentLines[:0]
		currentValues = make(map[string]string)
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			currentLines = append(currentLines, line)
			continue
		}
		if currentSection == "" {
			continue
		}
		currentLines = append(currentLines, line)
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		currentValues[normalizeKVKey(key)] = strings.TrimSpace(value)
	}
	flush()

	return matches
}

func inspectScopedCredentialFields(text string, seen map[string]struct{}) []Match {
	type scopeValues struct {
		lines []string
		user  string
		pass  string
	}
	scopes := make(map[string]*scopeValues)
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		key, value, ok := splitKeyValue(line)
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(key))
		kind, scope, ok := scopedCredentialField(normalized)
		if !ok {
			continue
		}
		entry := scopes[scope]
		if entry == nil {
			entry = &scopeValues{}
			scopes[scope] = entry
		}
		entry.lines = append(entry.lines, line)
		value = cleanConnectionValue(value)
		switch kind {
		case "user":
			entry.user = meaningfulConnectionCredentialValue(value)
		case "password":
			entry.pass = meaningfulConnectionCredentialValue(value)
		}
	}

	matches := make([]Match, 0, len(scopes))
	for scope, values := range scopes {
		if values.user == "" || values.pass == "" {
			continue
		}
		canonical := "driver=postgresql;database=" + scope + ";user=" + values.user + ";password=" + values.pass
		key := "dbinspect.access.connection_string::" + strings.ToLower(canonical)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, Match{
			ID:                  "dbinspect.access.connection_string",
			Name:                "Validated Database Connection Details",
			Description:         "Validated database configuration fields with authentication material were parsed within one datasource scope.",
			RuleType:            "content",
			SignalType:          "validated",
			Severity:            "high",
			Confidence:          "high",
			Category:            "database-access",
			Match:               scope,
			MatchedText:         canonical,
			MatchedTextRedacted: redactText(canonical),
			Snippet:             flatten(strings.Join(values.lines, " "), 160),
			Context:             limitRunes(strings.Join(values.lines, "\n"), 320),
			ContextRedacted:     limitRunes(redactText(strings.Join(values.lines, "\n")), 320),
			Explanation:         "This finding comes from explicit username and password fields within one database datasource namespace.",
			Remediation:         "Remove embedded database credentials from shared configuration files and move access details into managed secrets.",
			Tags:                []string{"database", "db:source:config", "db:type:config-credential", "db:ecosystem:postgresql"},
		})
	}
	return matches
}

func scopedCredentialField(key string) (kind, scope string, ok bool) {
	key = strings.TrimSpace(key)
	for _, suffix := range []string{".username", ".userid", ".user", ".uid", ".password", ".pwd"} {
		if strings.HasSuffix(key, suffix) && len(key) > len(suffix) {
			scope = strings.TrimSuffix(key, suffix)
			if !databaseCredentialScope(scope) {
				return "", "", false
			}
			if strings.Contains(suffix, "pass") || suffix == ".pwd" {
				return "password", scope, true
			}
			return "user", scope, true
		}
	}
	for _, suffix := range []string{"_username", "_userid", "_user", "_uid", "_password", "_pwd"} {
		if strings.HasSuffix(key, suffix) && len(key) > len(suffix) {
			scope = strings.TrimSuffix(key, suffix)
			if !databaseCredentialScope(scope) {
				return "", "", false
			}
			if strings.Contains(suffix, "pass") || suffix == "_pwd" {
				return "password", scope, true
			}
			return "user", scope, true
		}
	}
	return "", "", false
}

func databaseCredentialScope(scope string) bool {
	return strings.Contains(scope, "database") || strings.Contains(scope, "datasource") || strings.HasPrefix(scope, "db") || strings.Contains(scope, "connection")
}

func inspectINISection(section string, values map[string]string) (stringObservation, bool) {
	if len(values) == 0 {
		return stringObservation{}, false
	}

	driver := meaningfulValue(firstNonEmpty(values["driver"], values["provider"]))
	endpoint := meaningfulValue(firstNonEmpty(values["server"], values["host"], values["datasource"]))
	database := meaningfulValue(firstNonEmpty(values["database"], values["dbname"], values["dbq"]))
	user := meaningfulConnectionCredentialValue(firstNonEmpty(values["uid"], values["userid"], values["user"], values["username"]))
	password := meaningfulConnectionCredentialValue(firstNonEmpty(values["password"], values["pwd"]))
	if driver == "" && endpoint == "" && database == "" && user == "" && password == "" {
		return stringObservation{}, false
	}
	if driver == "" && endpoint == "" && database == "" {
		return stringObservation{}, false
	}

	ecosystem := detectEcosystem(values)
	if ecosystem == "" {
		ecosystem = "odbc"
	}

	matchText := strings.TrimSpace(section)
	if endpoint != "" {
		matchText += " -> " + endpoint
	}
	if database != "" {
		matchText += "/" + database
	}

	tags := []string{"database", "db:source:config", "db:ecosystem:" + ecosystem}
	// Only an actual password makes this a credential; a user with no password
	// (or integrated security) is a configuration/infrastructure artifact.
	if password != "" && user != "" {
		return stringObservation{
			category:    "database-access",
			severity:    "high",
			confidence:  "high",
			id:          "dbinspect.access.dsn",
			name:        "Validated Database DSN Credentials",
			description: "Validated DSN-style configuration includes database access details or authentication material.",
			explanation: "This finding comes from structured DSN-style configuration parsing with authentication fields present.",
			remediation: "Remove embedded database credentials from DSN files, rotate exposed values, and store access details in managed secrets instead.",
			match:       matchText,
			lineNumber:  0,
			tags:        append(tags, "db:type:config-credential"),
		}, true
	}

	if endpoint == "" && database == "" {
		return stringObservation{}, false
	}

	return stringObservation{
		category:    "database-infrastructure",
		severity:    "medium",
		confidence:  "high",
		id:          "dbinspect.infrastructure.dsn",
		name:        "Validated Database DSN Indicator",
		description: "Validated DSN or database client configuration details were parsed from an INI-style section.",
		explanation: "This finding comes from structured DSN-style configuration parsing.",
		remediation: "Review whether this DSN configuration should be present in the share and restrict access to database client configuration files.",
		match:       matchText,
		lineNumber:  0,
		tags:        append(tags, "db:type:server-indicator"),
	}, true
}

func inspectKVFragment(fragment string, lineNumber int) (stringObservation, bool) {
	// Do not strip a terminal quote from the whole fragment: PostgreSQL
	// keyword/value strings commonly end with a quoted password.
	candidate := strings.TrimSpace(fragment)
	if !strings.Contains(candidate, "=") {
		return stringObservation{}, false
	}

	values, count := parseSemicolonKV(candidate)
	if !strings.Contains(candidate, ";") {
		values, count = parseKeywordKV(candidate)
	}
	if count < 2 {
		return stringObservation{}, false
	}

	ecosystem := ecosystemOrFallback(detectEcosystem(values), values)
	auth := authSummary(values)
	endpoint := meaningfulValue(firstNonEmpty(values["server"], values["host"], values["datasource"], values["dsn"]))
	database := meaningfulValue(firstNonEmpty(values["database"], values["dbname"], values["initialcatalog"], values["servicename"], values["sid"]))
	driver := meaningfulValue(firstNonEmpty(values["driver"], values["provider"]))
	if endpoint == "" && database == "" && driver == "" {
		return stringObservation{}, false
	}

	// A connection string is only a recovered *credential* when it carries an
	// actual non-placeholder, non-masked password. An account name with an empty
	// or absent password (for example the ubiquitous Access/Jet
	// "User ID=Admin;Password=\"\"") is a configuration artifact, not a secret.
	if auth.password != "" && auth.user != "" {
		return stringObservation{
			category:    "database-access",
			severity:    "high",
			confidence:  "high",
			id:          "dbinspect.access.connection_string",
			name:        "Validated Database Connection Details",
			description: "Validated database connection details with authentication material were parsed from a configuration string.",
			explanation: "This finding comes from parsed connection-string structure rather than a single keyword match.",
			remediation: "Remove embedded database credentials from shared configuration files, rotate exposed values, and move connection secrets into managed storage.",
			match:       summarizeConnection(values),
			lineNumber:  lineNumber,
			tags: []string{
				"database",
				"db:source:config",
				"db:type:config-credential",
				"db:ecosystem:" + ecosystem,
			},
		}, true
	}

	return stringObservation{
		category:    "database-infrastructure",
		severity:    "medium",
		confidence:  "high",
		id:          "dbinspect.infrastructure.connection_string",
		name:        "Validated Database Server Indicator",
		description: "Validated database infrastructure details were parsed from a connection string.",
		explanation: "This finding comes from parsed connection-string structure rather than a broad regex hit.",
		remediation: "Review whether this database connection detail should be present in the share and limit access to operational configuration files.",
		match:       summarizeConnection(values),
		lineNumber:  lineNumber,
		tags: []string{
			"database",
			"db:source:config",
			"db:type:server-indicator",
			"db:ecosystem:" + ecosystem,
		},
	}, true
}

func inspectURLFragment(fragment string, lineNumber int) (stringObservation, bool) {
	candidate := trimWrapper(fragment)
	lower := strings.ToLower(candidate)
	switch {
	case strings.HasPrefix(lower, "jdbc:sqlserver://"):
		return inspectJDBCSQLServer(candidate, lineNumber)
	case strings.HasPrefix(lower, "jdbc:mysql://"), strings.HasPrefix(lower, "jdbc:postgresql://"), strings.HasPrefix(lower, "jdbc:sqlite:"):
		return inspectJDBCURL(candidate, lineNumber)
	case strings.HasPrefix(lower, "jdbc:oracle:"):
		return inspectJDBCOracle(candidate, lineNumber)
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"), strings.HasPrefix(lower, "mysql://"), strings.HasPrefix(lower, "mariadb://"), strings.HasPrefix(lower, "sqlserver://"):
		return inspectDBURL(candidate, lineNumber)
	default:
		return stringObservation{}, false
	}
}

func inspectJDBCSQLServer(candidate string, lineNumber int) (stringObservation, bool) {
	trimmed := trimWrapper(candidate)
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "jdbc:sqlserver://"), ";", 2)
	if len(parts) != 2 || meaningfulValue(parts[0]) == "" {
		return stringObservation{}, false
	}
	values, count := parseSemicolonKV(parts[1])
	if count == 0 {
		return stringObservation{}, false
	}
	values["server"] = strings.TrimSpace(parts[0])
	return inspectKVFragment(summarizeKV(values), lineNumber)
}

func inspectJDBCURL(candidate string, lineNumber int) (stringObservation, bool) {
	trimmed := trimWrapper(strings.TrimPrefix(candidate, "jdbc:"))
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" {
		if values, ok := parseRawDatabaseURL(trimmed); ok {
			return inspectKVFragment(summarizeKV(values), lineNumber)
		}
		return stringObservation{}, false
	}

	values := map[string]string{
		"driver":   parsed.Scheme,
		"server":   parsed.Hostname(),
		"database": strings.TrimPrefix(parsed.Path, "/"),
		"user":     parsed.User.Username(),
	}
	if password, ok := parsed.User.Password(); ok {
		values["password"] = password
	}
	for key, list := range parsed.Query() {
		if len(list) == 0 {
			continue
		}
		values[normalizeKVKey(key)] = list[0]
	}
	if meaningfulValue(values["server"]) == "" && meaningfulValue(values["database"]) == "" {
		return stringObservation{}, false
	}
	return inspectKVFragment(summarizeKV(values), lineNumber)
}

func inspectJDBCOracle(candidate string, lineNumber int) (stringObservation, bool) {
	trimmed := trimWrapper(candidate)
	matches := jdbcOracleRegex.FindStringSubmatch(trimmed)
	if len(matches) != 4 {
		return stringObservation{}, false
	}

	values := map[string]string{
		"driver":   "oracle",
		"server":   matches[1],
		"port":     matches[2],
		"database": matches[3],
	}
	return inspectKVFragment(summarizeKV(values), lineNumber)
}

func inspectDBURL(candidate string, lineNumber int) (stringObservation, bool) {
	trimmed := trimWrapper(candidate)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || meaningfulValue(parsed.Hostname()) == "" {
		if values, ok := parseRawDatabaseURL(trimmed); ok {
			return inspectKVFragment(summarizeKV(values), lineNumber)
		}
		return stringObservation{}, false
	}

	values := map[string]string{
		"driver":   parsed.Scheme,
		"server":   parsed.Hostname(),
		"database": strings.TrimPrefix(parsed.Path, "/"),
		"user":     parsed.User.Username(),
	}
	if password, ok := parsed.User.Password(); ok {
		values["password"] = password
	}
	for key, list := range parsed.Query() {
		if len(list) == 0 {
			continue
		}
		values[normalizeKVKey(key)] = list[0]
	}
	return inspectKVFragment(summarizeKV(values), lineNumber)
}

func parseRawDatabaseURL(value string) (map[string]string, bool) {
	schemeEnd := strings.Index(value, "://")
	if schemeEnd <= 0 {
		return nil, false
	}
	scheme := strings.ToLower(value[:schemeEnd])
	switch scheme {
	case "postgres", "postgresql", "mysql", "mariadb", "sqlserver":
	default:
		return nil, false
	}
	rest := value[schemeEnd+3:]
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return nil, false
	}
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon <= 0 || colon == len(userinfo)-1 {
		return nil, false
	}
	username, err := url.PathUnescape(userinfo[:colon])
	if err != nil {
		return nil, false
	}
	password, err := url.PathUnescape(userinfo[colon+1:])
	if err != nil || meaningfulValue(username) == "" || meaningfulValue(password) == "" {
		return nil, false
	}
	hostPart := rest[at+1:]
	hostEnd := strings.IndexAny(hostPart, "/?")
	if hostEnd >= 0 {
		hostPart = hostPart[:hostEnd]
	}
	if hostPart == "" {
		return nil, false
	}
	return map[string]string{"driver": scheme, "server": hostPart, "user": username, "password": password}, true
}

func matchFromObservation(observation stringObservation, raw string) Match {
	raw = strings.TrimSpace(raw)
	signalType := strings.TrimSpace(observation.signalType)
	if signalType == "" {
		signalType = "validated"
	}
	return Match{
		ID:                  observation.id,
		Name:                observation.name,
		Description:         observation.description,
		RuleType:            "content",
		SignalType:          signalType,
		Severity:            observation.severity,
		Confidence:          observation.confidence,
		Category:            observation.category,
		Match:               observation.match,
		MatchedText:         raw,
		MatchedTextRedacted: redactText(raw),
		Snippet:             flatten(raw, 160),
		Context:             limitRunes(raw, 320),
		ContextRedacted:     limitRunes(redactText(raw), 320),
		LineNumber:          observation.lineNumber,
		Explanation:         observation.explanation,
		Remediation:         observation.remediation,
		Tags:                append([]string{}, observation.tags...),
	}
}

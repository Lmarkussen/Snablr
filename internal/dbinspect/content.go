package dbinspect

import (
	"net/url"
	"strings"
)

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

func inspectINISection(section string, values map[string]string) (stringObservation, bool) {
	if len(values) == 0 {
		return stringObservation{}, false
	}

	driver := meaningfulValue(firstNonEmpty(values["driver"], values["provider"]))
	endpoint := meaningfulValue(firstNonEmpty(values["server"], values["host"], values["datasource"]))
	database := meaningfulValue(firstNonEmpty(values["database"], values["dbname"], values["dbq"]))
	user := meaningfulValue(firstNonEmpty(values["uid"], values["userid"], values["user"], values["username"]))
	password := meaningfulValue(firstNonEmpty(values["password"], values["pwd"]))
	if driver == "" && endpoint == "" && database == "" && user == "" && password == "" {
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
	if user != "" || password != "" {
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
			lineNumber:  1,
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
		lineNumber:  1,
		tags:        append(tags, "db:type:server-indicator"),
	}, true
}

func inspectKVFragment(fragment string, lineNumber int) (stringObservation, bool) {
	candidate := trimWrapper(fragment)
	if !strings.Contains(candidate, "=") || !strings.Contains(candidate, ";") {
		return stringObservation{}, false
	}

	values, count := parseSemicolonKV(candidate)
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

	if auth.password != "" || auth.user != "" || auth.integrated {
		severity := "high"
		if auth.password == "" {
			severity = "medium"
		}
		return stringObservation{
			category:    "database-access",
			severity:    severity,
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
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"), strings.HasPrefix(lower, "mysql://"):
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

func matchFromObservation(observation stringObservation, raw string) Match {
	raw = strings.TrimSpace(raw)
	return Match{
		ID:                  observation.id,
		Name:                observation.name,
		Description:         observation.description,
		RuleType:            "content",
		SignalType:          "validated",
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

package dbinspect

import (
	"fmt"
	"strings"
)

// sqlDumpLiteralDataRowThreshold is the number of literal data rows (values
// tuples that actually carry a quoted string or a numeric literal) required
// before a .sql file with no self-identifying dump markers is treated as a
// data-bearing export on volume alone. It is intentionally well above the
// handful of seed rows a migration or install script inserts.
const sqlDumpLiteralDataRowThreshold = 100

func inspectSQLDump(candidate Candidate, text string, seen map[string]struct{}) []Match {
	if normalizedExtension(candidate) != ".sql" {
		return nil
	}

	headerObservation, hasHeader := inspectSQLDumpHeader(text)
	dumpObservation, hasDump := inspectSQLDumpStructure(text)
	scriptObservation, hasScript := inspectSQLScriptArtifact(text)
	if !hasHeader && !hasDump && !hasScript {
		return nil
	}

	var matches []Match
	appendObservation := func(observation stringObservation) {
		key := observation.id + "::" + strings.ToLower(observation.match)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		matches = append(matches, matchFromObservation(observation, text))
	}
	if hasHeader {
		appendObservation(headerObservation)
	}
	if hasDump {
		appendObservation(dumpObservation)
	}
	if hasScript {
		appendObservation(scriptObservation)
	}
	return matches
}

func inspectSQLDumpHeader(text string) (stringObservation, bool) {
	switch {
	case sqlMySQLDumpRegex.MatchString(text):
		return dumpHeaderObservation("MySQL dump header", "mysql"), true
	case sqlPgDumpRegex.MatchString(text):
		return dumpHeaderObservation("PostgreSQL dump header", "postgresql"), true
	default:
		return stringObservation{}, false
	}
}

func dumpHeaderObservation(match, ecosystem string) stringObservation {
	return stringObservation{
		category:    "database-artifacts",
		severity:    "high",
		confidence:  "high",
		id:          "dbinspect.artifact.sql_dump_header",
		name:        "Validated SQL Dump Header",
		description: "Validated dump-tool style SQL export headers were identified.",
		explanation: "This finding is based on dump-tool style SQL header markers rather than a generic .sql extension.",
		remediation: "Review whether this SQL export belongs on the share, remove unnecessary copies, and restrict access to retained database dumps.",
		match:       match,
		lineNumber:  1,
		tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:dump-export",
			"db:ecosystem:" + ecosystem,
		},
		signalType: "validated",
	}
}

// sqlStructureProfile summarises the SQL statement mix of a .sql file so the
// classifier can separate schema/application scripts from data-bearing dumps.
type sqlStructureProfile struct {
	createTables      int
	alterTables       int
	createIndexes     int
	createRoutines    int
	insertInto        int
	literalDataRows   int
	dropTableIfExists int
	lockTables        int
	unlockTables      int
	copyFromStdin     int
	hasDumpMarker     bool
	hasBackupSyntax   bool
	procedural        bool
}

func profileSQL(text string) sqlStructureProfile {
	profile := sqlStructureProfile{
		createTables:      len(sqlCreateTable.FindAllStringIndex(text, -1)),
		alterTables:       len(sqlAlterTable.FindAllStringIndex(text, -1)),
		createIndexes:     len(sqlCreateIndex.FindAllStringIndex(text, -1)),
		createRoutines:    len(sqlCreateRoutine.FindAllStringIndex(text, -1)),
		insertInto:        len(sqlInsertInto.FindAllStringIndex(text, -1)),
		literalDataRows:   countSQLLiteralDataRows(text),
		dropTableIfExists: len(sqlDropIfExists.FindAllStringIndex(text, -1)),
		lockTables:        len(sqlLockTables.FindAllStringIndex(text, -1)),
		unlockTables:      len(sqlUnlockTables.FindAllStringIndex(text, -1)),
		copyFromStdin:     len(sqlCopyFromStdin.FindAllStringIndex(text, -1)),
	}
	profile.hasDumpMarker = sqlDumpDataMarker.MatchString(text)
	profile.hasBackupSyntax = sqlBackupSyntax.MatchString(text)
	// Procedural/batch markers describe an application script rather than a
	// table export.
	profile.procedural = profile.createRoutines > 0 ||
		sqlBatchSeparator.MatchString(text) ||
		sqlDeclareVariable.MatchString(text)
	return profile
}

// dumpEvidence reports whether the profile carries enough structural evidence
// to call the file a data-bearing SQL dump/export, and returns the evidence it
// used. Only data-bearing structure qualifies; DDL alone does not.
func (profile sqlStructureProfile) dumpEvidence() (string, bool) {
	switch {
	case profile.copyFromStdin > 0:
		return fmt.Sprintf("COPY ... FROM stdin x%d", profile.copyFromStdin), true
	case profile.hasDumpMarker:
		return "dump-tool data-section markers", true
	case profile.hasBackupSyntax:
		return "explicit backup/export statement", true
	case profile.lockTables > 0 && profile.unlockTables > 0 && profile.literalDataRows > 0:
		return fmt.Sprintf("LOCK TABLES/UNLOCK TABLES with INSERT ... VALUES x%d", profile.literalDataRows), true
	case !profile.procedural && profile.literalDataRows >= sqlDumpLiteralDataRowThreshold:
		return fmt.Sprintf("INSERT INTO ... VALUES x%d", profile.literalDataRows), true
	default:
		return "", false
	}
}

// hasScriptStructure reports whether the file shows schema, DDL or procedural
// structure worth surfacing at low severity. A file with literal data but no
// schema/procedural structure is not a "script" and is left to the dump
// classifier.
func (profile sqlStructureProfile) hasScriptStructure() bool {
	if profile.createTables > 0 || profile.createRoutines > 0 {
		return true
	}
	return profile.legacyDumpStructureFired()
}

// legacyDumpStructureFired reproduces the previous non-data structure heuristic.
// It is kept so files that previously produced a structure finding continue to
// surface (now at low severity) when they carry no data-bearing export
// evidence.
func (profile sqlStructureProfile) legacyDumpStructureFired() bool {
	switch {
	case profile.copyFromStdin > 0:
		return true
	case profile.createTables >= 2 && (profile.insertInto >= 1 || profile.dropTableIfExists >= 1 || (profile.lockTables > 0 && profile.unlockTables > 0)):
		return true
	case profile.insertInto >= 2 && (profile.createTables >= 1 || profile.dropTableIfExists >= 1 || (profile.lockTables > 0 && profile.unlockTables > 0)):
		return true
	case profile.insertInto >= 3:
		return true
	case profile.createTables >= 3:
		return true
	default:
		return false
	}
}

func inspectSQLDumpStructure(text string) (stringObservation, bool) {
	profile := profileSQL(text)
	evidence, ok := profile.dumpEvidence()
	if !ok {
		return stringObservation{}, false
	}

	severity := "medium"
	confidence := "medium"
	switch {
	case profile.copyFromStdin > 0, profile.hasDumpMarker, profile.hasBackupSyntax, profile.lockTables > 0 && profile.unlockTables > 0:
		severity = "high"
		confidence = "high"
	}

	return stringObservation{
		category:    "database-artifacts",
		severity:    severity,
		confidence:  confidence,
		id:          "dbinspect.artifact.sql_dump_structure",
		name:        "Likely SQL Data Dump Or Export",
		description: "Data-bearing SQL export structure was identified, such as a bulk COPY block, dump-tool data markers, or a large volume of literal row values.",
		explanation: "This finding is based on data-bearing SQL export structure rather than schema/DDL statements or a generic .sql extension.",
		remediation: "Review whether this SQL export belongs on the share, remove unnecessary copies, and restrict access to retained database dumps.",
		match:       evidence,
		lineNumber:  1,
		tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:dump-export",
			"db:ecosystem:generic",
		},
		signalType: "content",
	}, true
}

// inspectSQLScriptArtifact classifies a .sql file that carries schema, DDL or
// procedural structure but no data-bearing export evidence. It is emitted at
// low severity so review visibility is preserved without presenting a schema or
// install script as a high-severity database dump.
func inspectSQLScriptArtifact(text string) (stringObservation, bool) {
	profile := profileSQL(text)
	if _, isDump := profile.dumpEvidence(); isDump {
		return stringObservation{}, false
	}
	if !profile.hasScriptStructure() {
		return stringObservation{}, false
	}

	parts := make([]string, 0, 6)
	if profile.createTables > 0 {
		parts = append(parts, fmt.Sprintf("CREATE TABLE x%d", profile.createTables))
	}
	if profile.alterTables > 0 {
		parts = append(parts, fmt.Sprintf("ALTER TABLE x%d", profile.alterTables))
	}
	if profile.createIndexes > 0 {
		parts = append(parts, fmt.Sprintf("CREATE INDEX x%d", profile.createIndexes))
	}
	if profile.createRoutines > 0 {
		parts = append(parts, fmt.Sprintf("CREATE ROUTINE x%d", profile.createRoutines))
	}
	if profile.insertInto > 0 {
		parts = append(parts, fmt.Sprintf("INSERT INTO x%d", profile.insertInto))
	}
	if len(parts) == 0 {
		parts = append(parts, "SQL statements")
	}

	return stringObservation{
		category:    "database-artifacts",
		severity:    "low",
		confidence:  "low",
		id:          "dbinspect.artifact.sql_script",
		name:        "SQL Script Or Schema Artifact",
		description: "Schema, migration or install-style SQL statements were identified. This is an application or schema script rather than a data export.",
		explanation: "This finding is based on DDL, schema and script structure with no data-bearing export evidence, so it is reported for review rather than as a dump.",
		remediation: "Review whether this SQL script belongs on the share, remove obsolete copies, and confirm it does not embed credentials or sensitive data.",
		match:       strings.Join(parts, "; "),
		lineNumber:  1,
		tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:schema-script",
			"db:ecosystem:generic",
		},
		signalType: "content",
	}, true
}

// countSQLLiteralDataRows counts VALUES tuples that actually carry literal data
// (a quoted string or a numeric literal). Tuples made only of SQL variables,
// function calls or other expressions are not data and are not counted, so
// procedure bodies and scripts do not inflate the data-row volume.
func countSQLLiteralDataRows(text string) int {
	rows := 0
	for _, location := range sqlInsertValues.FindAllStringIndex(text, -1) {
		start := location[1]
		end := len(text)
		if idx := strings.IndexByte(text[start:], ';'); idx >= 0 {
			end = start + idx
		}
		if end-start > 1<<20 {
			end = start + (1 << 20)
		}
		rows += countValuesLiteralTuples(text[start:end])
	}
	return rows
}

func countValuesLiteralTuples(values string) int {
	count := 0
	index := 0
	for index < len(values) {
		for index < len(values) && isValuesSeparator(values[index]) {
			index++
		}
		if index >= len(values) || values[index] != '(' {
			break
		}
		tuple, next := scanParenthesized(values, index)
		if next <= index {
			break
		}
		if tupleHasLiteralData(tuple) {
			count++
		}
		index = next
	}
	return count
}

func isValuesSeparator(char byte) bool {
	switch char {
	case ' ', '\t', '\r', '\n', ',':
		return true
	default:
		return false
	}
}

// scanParenthesized returns the balanced parenthesised span starting at start
// and the index just past it, honouring single- and double-quoted strings.
func scanParenthesized(text string, start int) (string, int) {
	depth := 0
	inSingle := false
	inDouble := false
	for index := start; index < len(text); index++ {
		char := text[index]
		switch {
		case inSingle:
			if char == '\\' {
				index++
				continue
			}
			if char == '\'' {
				inSingle = false
			}
		case inDouble:
			if char == '\\' {
				index++
				continue
			}
			if char == '"' {
				inDouble = false
			}
		default:
			switch char {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return text[start : index+1], index + 1
				}
			}
		}
	}
	return "", start
}

// splitTopLevelFields splits a tuple body on commas that are not nested inside
// parentheses or string literals.
func splitTopLevelFields(body string) []string {
	fields := make([]string, 0, 4)
	depth := 0
	inSingle := false
	inDouble := false
	start := 0
	for index := 0; index < len(body); index++ {
		char := body[index]
		switch {
		case inSingle:
			if char == '\\' {
				index++
				continue
			}
			if char == '\'' {
				inSingle = false
			}
		case inDouble:
			if char == '\\' {
				index++
				continue
			}
			if char == '"' {
				inDouble = false
			}
		default:
			switch char {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '(':
				depth++
			case ')':
				if depth > 0 {
					depth--
				}
			case ',':
				if depth == 0 {
					fields = append(fields, body[start:index])
					start = index + 1
				}
			}
		}
	}
	fields = append(fields, body[start:])
	return fields
}

func tupleHasLiteralData(tuple string) bool {
	body := strings.TrimSpace(tuple)
	if strings.HasPrefix(body, "(") && strings.HasSuffix(body, ")") {
		body = body[1 : len(body)-1]
	}
	for _, field := range splitTopLevelFields(body) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if strings.ContainsAny(field, "'\"") {
			return true
		}
		if isNumericLiteral(field) {
			return true
		}
	}
	return false
}

func isNumericLiteral(field string) bool {
	if field == "" {
		return false
	}
	index := 0
	if field[0] == '+' || field[0] == '-' {
		index++
	}
	digits := 0
	dot := false
	for ; index < len(field); index++ {
		char := field[index]
		switch {
		case char >= '0' && char <= '9':
			digits++
		case char == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0
}

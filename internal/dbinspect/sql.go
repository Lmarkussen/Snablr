package dbinspect

import (
	"fmt"
	"strings"
)

func inspectSQLDump(candidate Candidate, text string, seen map[string]struct{}) []Match {
	if normalizedExtension(candidate) != ".sql" {
		return nil
	}

	headerObservation, hasHeader := inspectSQLDumpHeader(text)
	structureObservation, hasStructure := inspectSQLDumpStructure(text)
	if !hasHeader && !hasStructure {
		return nil
	}

	var matches []Match
	if hasHeader {
		key := headerObservation.id + "::" + strings.ToLower(headerObservation.match)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			matches = append(matches, matchFromObservation(headerObservation, text))
		}
	}
	if hasStructure {
		key := structureObservation.id + "::" + strings.ToLower(structureObservation.match)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			matches = append(matches, matchFromObservation(structureObservation, text))
		}
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

func inspectSQLDumpStructure(text string) (stringObservation, bool) {
	createCount := len(sqlCreateTable.FindAllStringIndex(text, -1))
	insertCount := len(sqlInsertInto.FindAllStringIndex(text, -1))
	dropCount := len(sqlDropIfExists.FindAllStringIndex(text, -1))
	copyCount := len(sqlCopyFromStdin.FindAllStringIndex(text, -1))
	lockCount := len(sqlLockTables.FindAllStringIndex(text, -1))
	unlockCount := len(sqlUnlockTables.FindAllStringIndex(text, -1))

	switch {
	case copyCount > 0:
		return dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount), true
	case createCount >= 2 && (insertCount >= 1 || dropCount >= 1 || (lockCount > 0 && unlockCount > 0)):
		return dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount), true
	case insertCount >= 2 && (createCount >= 1 || dropCount >= 1 || (lockCount > 0 && unlockCount > 0)):
		return dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount), true
	case insertCount >= 3:
		return dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount), true
	case createCount >= 3:
		return dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount), true
	default:
		return stringObservation{}, false
	}
}

func dumpStructureObservation(createCount, insertCount, dropCount, copyCount, lockCount, unlockCount int) stringObservation {
	parts := make([]string, 0, 6)
	if createCount > 0 {
		parts = append(parts, fmt.Sprintf("CREATE TABLE x%d", createCount))
	}
	if insertCount > 0 {
		parts = append(parts, fmt.Sprintf("INSERT INTO x%d", insertCount))
	}
	if dropCount > 0 {
		parts = append(parts, fmt.Sprintf("DROP TABLE IF EXISTS x%d", dropCount))
	}
	if copyCount > 0 {
		parts = append(parts, fmt.Sprintf("COPY ... FROM stdin x%d", copyCount))
	}
	if lockCount > 0 {
		parts = append(parts, fmt.Sprintf("LOCK TABLES x%d", lockCount))
	}
	if unlockCount > 0 {
		parts = append(parts, fmt.Sprintf("UNLOCK TABLES x%d", unlockCount))
	}

	return stringObservation{
		category:    "database-artifacts",
		severity:    "high",
		confidence:  "medium",
		id:          "dbinspect.artifact.sql_dump_structure",
		name:        "Likely SQL Dump Or Export Structure",
		description: "Repeated schema/data export statements suggest this SQL file is a real database dump or export rather than a small migration script.",
		explanation: "This finding is based on repeated SQL dump/export structures rather than a generic .sql extension.",
		remediation: "Review whether this SQL export belongs on the share, remove unnecessary copies, and restrict access to retained database dumps.",
		match:       strings.Join(parts, "; "),
		lineNumber:  1,
		tags: []string{
			"database",
			"db:source:local-artifact",
			"db:type:dump-export",
			"db:ecosystem:generic",
		},
		signalType: "content",
	}
}

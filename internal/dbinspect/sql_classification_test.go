package dbinspect

import (
	"strconv"
	"strings"
	"testing"
)

func inspectSQLText(text string) []Match {
	candidate := Candidate{FilePath: "sample.sql", Name: "sample.sql", Extension: ".sql", Size: int64(len(text))}
	return New().InspectContent(candidate, []byte(text))
}

func findingIDs(matches []Match) map[string]Match {
	out := make(map[string]Match, len(matches))
	for _, match := range matches {
		out[match.ID] = match
	}
	return out
}

func TestSQLClassificationMatrix(t *testing.T) {
	t.Parallel()

	seedRows := func(count int) string {
		var builder strings.Builder
		for index := 0; index < count; index++ {
			builder.WriteString("INSERT INTO t (id, name) VALUES (")
			builder.WriteString(strconv.Itoa(index))
			builder.WriteString(", 'value-")
			builder.WriteString(strconv.Itoa(index))
			builder.WriteString("');\n")
		}
		return builder.String()
	}

	tests := []struct {
		name         string
		sql          string
		wantDump     bool
		wantHighDump bool
		wantScript   bool
	}{
		{
			name: "ddl only schema script",
			sql: "CREATE TABLE users (id int);\n" +
				"ALTER TABLE users ADD COLUMN name varchar(64);\n" +
				"CREATE INDEX idx_users_name ON users (name);\n",
			wantDump:   false,
			wantScript: true,
		},
		{
			name: "stored procedure installer",
			sql: "CREATE TABLE dbo.stage (id int, name varchar(64));\nGO\n" +
				"CREATE PROCEDURE dbo.sync AS\nBEGIN\n" +
				"  DECLARE @counter int;\n" +
				"  SET @counter = 1;\n" +
				"  EXEC dbo.helper @counter;\n" +
				"END\nGO\n",
			wantDump:   false,
			wantScript: true,
		},
		{
			name: "small seed migration",
			sql: "CREATE TABLE roles (id int, name varchar(32));\n" +
				"ALTER TABLE roles ADD CONSTRAINT pk_roles PRIMARY KEY (id);\n" +
				"INSERT INTO roles (id, name) VALUES (1, 'admin');\n" +
				"INSERT INTO roles (id, name) VALUES (2, 'user');\n" +
				"INSERT INTO roles (id, name) VALUES (3, 'auditor');\n",
			wantDump:   false,
			wantScript: true,
		},
		{
			name:         "large literal data dump",
			sql:          "CREATE TABLE t (id int, name varchar(64));\n" + seedRows(250),
			wantDump:     true,
			wantHighDump: false,
		},
		{
			name: "mysqldump style export",
			sql: "-- MySQL dump 10.13  Distrib 8.0.36\nDROP TABLE IF EXISTS `users`;\n" +
				"CREATE TABLE `users` (`id` int, `name` varchar(64));\n" +
				"LOCK TABLES `users` WRITE;\nINSERT INTO `users` VALUES (1,'alice');\n" +
				"INSERT INTO `users` VALUES (2,'bob');\nUNLOCK TABLES;\n",
			wantDump:     true,
			wantHighDump: true,
		},
		{
			name: "pg_dump copy export",
			sql: "-- PostgreSQL database dump\n-- Dumped by pg_dump version 15\n" +
				"CREATE TABLE public.users (id integer, name text);\n" +
				"COPY public.users (id, name) FROM stdin;\n1\talice\n2\tbob\n\\.\n",
			wantDump:     true,
			wantHighDump: true,
		},
		{
			name: "mixed schema with large data",
			sql: "CREATE TABLE audit (id int, detail varchar(128));\n" +
				"ALTER TABLE audit ADD COLUMN created_at timestamp;\n" + seedRows(180),
			wantDump:     true,
			wantHighDump: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matches := inspectSQLText(test.sql)
			byID := findingIDs(matches)

			_, hasDump := byID["dbinspect.artifact.sql_dump_structure"]
			if hasDump != test.wantDump {
				t.Fatalf("dump structure presence = %v, want %v (matches=%#v)", hasDump, test.wantDump, matches)
			}
			if hasDump {
				dump := byID["dbinspect.artifact.sql_dump_structure"]
				isHigh := strings.EqualFold(dump.Severity, "high")
				if isHigh != test.wantHighDump {
					t.Fatalf("dump severity high = %v, want %v (severity=%s)", isHigh, test.wantHighDump, dump.Severity)
				}
			}
			_, hasScript := byID["dbinspect.artifact.sql_script"]
			if hasScript != test.wantScript {
				t.Fatalf("script artifact presence = %v, want %v (matches=%#v)", hasScript, test.wantScript, matches)
			}
			if hasScript {
				script := byID["dbinspect.artifact.sql_script"]
				if !strings.EqualFold(script.Severity, "low") {
					t.Fatalf("script artifact severity = %s, want low", script.Severity)
				}
			}
			// A schema/script artifact must never coexist with a dump finding.
			if hasDump && hasScript {
				t.Fatalf("file classified as both dump and script: %#v", matches)
			}
		})
	}
}

func TestSQLDDLOnlyNeverProducesHighSeverityDump(t *testing.T) {
	t.Parallel()

	schema := "CREATE TABLE a (id int);\nCREATE TABLE b (id int);\nCREATE TABLE c (id int);\n" +
		"ALTER TABLE a ADD COLUMN x int;\nCREATE INDEX idx_a ON a (id);\nCREATE PROCEDURE p AS SELECT 1;\nGO\n"
	for _, match := range inspectSQLText(schema) {
		if match.ID == "dbinspect.artifact.sql_dump_structure" {
			t.Fatalf("DDL-only schema was classified as a dump: %#v", match)
		}
	}
}

package seed

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type sqliteSeedTable struct {
	Name    string
	Columns []string
	Rows    [][]string
}

func renderSQLiteSeed(style string, ctx renderContext) []byte {
	tables := sqliteTablesForStyle(style, ctx)
	if len(tables) == 0 {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "snablr-seed-*.db")
	if err != nil {
		return text("SYNTHETIC SQLITE PLACEHOLDER")
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite3", tmpPath)
	if err != nil {
		return text("SYNTHETIC SQLITE PLACEHOLDER")
	}
	defer db.Close()

	for _, table := range tables {
		if _, err := db.Exec(buildCreateTableSQL(table)); err != nil {
			return text("SYNTHETIC SQLITE PLACEHOLDER")
		}
		for _, row := range table.Rows {
			stmt, args := buildInsertSQL(table, row)
			if _, err := db.Exec(stmt, args...); err != nil {
				return text("SYNTHETIC SQLITE PLACEHOLDER")
			}
		}
	}
	_ = db.Close()

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return text("SYNTHETIC SQLITE PLACEHOLDER")
	}
	return content
}

func isSQLiteSeedStyle(style string) bool {
	switch style {
	case "sqlite-credential-db", "sqlite-token-db", "sqlite-benign-db", "sqlite-correlation-db":
		return true
	default:
		return false
	}
}

func validateSQLiteSeed(content []byte, style string, ctx renderContext) error {
	if len(content) < 16 || string(content[:16]) != "SQLite format 3\x00" {
		return fmt.Errorf("sqlite seed %q was not generated as a real SQLite database (missing SQLite header); check CGO and gcc availability", style)
	}

	tmpFile, err := os.CreateTemp("", "snablr-seed-validate-*.db")
	if err != nil {
		return fmt.Errorf("create sqlite validation temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write sqlite validation temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close sqlite validation temp file: %w", err)
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_query_only=1", tmpPath))
	if err != nil {
		return fmt.Errorf("open generated sqlite seed %q: %w", style, err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping generated sqlite seed %q: %w", style, err)
	}

	tables := sqliteTablesForStyle(style, ctx)
	if len(tables) == 0 {
		return fmt.Errorf("sqlite seed %q has no expected tables", style)
	}
	for _, table := range tables {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table.Name).Scan(&exists); err != nil {
			return fmt.Errorf("inspect sqlite seed table %q: %w", table.Name, err)
		}
		if exists != 1 {
			return fmt.Errorf("sqlite seed %q is missing expected table %q", style, table.Name)
		}
		var rows int
		if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteSQLiteIdent(table.Name))).Scan(&rows); err != nil {
			return fmt.Errorf("read sqlite seed table %q: %w", table.Name, err)
		}
		if rows < 1 {
			return fmt.Errorf("sqlite seed %q table %q has no rows", style, table.Name)
		}
	}
	return nil
}

func quoteSQLiteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func sqliteTablesForStyle(style string, ctx renderContext) []sqliteSeedTable {
	switch style {
	case "sqlite-credential-db":
		return []sqliteSeedTable{
			{
				Name:    "users",
				Columns: []string{"id INTEGER", "username TEXT", "password TEXT", "api_key TEXT"},
				Rows: [][]string{
					{"1", dbUserValue(ctx), dbPasswordValue(ctx), apiKeyValue(ctx)},
					{"2", "synthetic_reader", "RotateMeNow!2025", "SYNTHETIC_API_TOKEN_ONLY_ABC123"},
				},
			},
			{
				Name:    "settings",
				Columns: []string{"key TEXT", "value TEXT"},
				Rows: [][]string{
					{"db_connection_string", postgresConnectionURLValue(ctx)},
					{"backup_encryption_key", backupPasswordValue(ctx)},
				},
			},
		}
	case "sqlite-token-db":
		return []sqliteSeedTable{
			{
				Name:    "sessions",
				Columns: []string{"id INTEGER", "username TEXT", "token TEXT", "client_secret TEXT"},
				Rows: [][]string{
					{"1", personaValue(ctx), tokenValue(ctx), clientSecretValue(ctx)},
					{"2", serviceAccountValue(ctx), "SYNTHETIC_REFRESH_TOKEN_ABC987654321", "SYNTHETIC_CLIENT_SECRET_ONLY_XYZ987654321"},
				},
			},
		}
	case "sqlite-benign-db":
		return []sqliteSeedTable{
			{
				Name:    "metrics",
				Columns: []string{"id INTEGER", "metric_name TEXT", "metric_value TEXT"},
				Rows: [][]string{
					{"1", "requests_total", "120"},
					{"2", "status", "green"},
				},
			},
			{
				Name:    "preferences",
				Columns: []string{"owner TEXT", "theme TEXT"},
				Rows: [][]string{
					{personaValue(ctx), "light"},
				},
			},
		}
	case "sqlite-correlation-db":
		return []sqliteSeedTable{
			{
				Name:    "accounts",
				Columns: []string{"id INTEGER", "username TEXT", "password TEXT"},
				Rows: [][]string{
					{"1", dbUserValue(ctx), dbPasswordValue(ctx)},
				},
			},
			{
				Name:    "config",
				Columns: []string{"name TEXT", "connection_string TEXT"},
				Rows: [][]string{
					{"primary", mssqlConnectionStringValue(ctx)},
				},
			},
		}
	default:
		return nil
	}
}

func buildCreateTableSQL(table sqliteSeedTable) string {
	return fmt.Sprintf("CREATE TABLE %q (%s)", table.Name, joinSQLColumns(table.Columns))
}

func joinSQLColumns(columns []string) string {
	out := ""
	for idx, column := range columns {
		if idx > 0 {
			out += ", "
		}
		out += column
	}
	return out
}

func buildInsertSQL(table sqliteSeedTable, row []string) (string, []any) {
	placeholders := make([]string, 0, len(row))
	args := make([]any, 0, len(row))
	for _, value := range row {
		placeholders = append(placeholders, "?")
		args = append(args, value)
	}
	stmt := fmt.Sprintf("INSERT INTO %q VALUES (%s)", table.Name, joinSQLColumns(placeholders))
	return stmt, args
}

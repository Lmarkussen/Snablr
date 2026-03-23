package seed

import (
	"database/sql"
	"fmt"
	"os"

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

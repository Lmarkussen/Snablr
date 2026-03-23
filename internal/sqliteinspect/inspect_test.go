package sqliteinspect

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInspectContentFindsSensitiveSQLiteValues(t *testing.T) {
	t.Parallel()

	content := buildSQLiteFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'Synthet!cPass2025')`,
		`CREATE TABLE settings (name TEXT, connection_string TEXT)`,
		`INSERT INTO settings VALUES ('primary', 'Server=sql01.lab.invalid;Database=Finance;UID=svc_finance;PWD=Synthet!cPass2025')`,
	})

	inspector := New(Options{Enabled: true})
	matches := inspector.InspectContent(Candidate{
		FilePath:  "Apps/finance.sqlite",
		Name:      "finance.sqlite",
		Extension: ".sqlite",
		Size:      int64(len(content)),
	}, content)
	if len(matches) == 0 {
		t.Fatal("expected sqlite inspector to return matches")
	}

	foundPassword := false
	foundConn := false
	for _, match := range matches {
		if match.DatabaseTable == "users" && match.DatabaseColumn == "password" {
			foundPassword = true
		}
		if match.DatabaseTable == "settings" && match.DatabaseColumn == "connection_string" {
			foundConn = true
		}
	}
	if !foundPassword || !foundConn {
		t.Fatalf("expected password and connection string matches, got %#v", matches)
	}
}

func TestInspectContentSkipsBenignSQLiteValues(t *testing.T) {
	t.Parallel()

	content := buildSQLiteFixture(t, []string{
		`CREATE TABLE metrics (id INTEGER, metric_name TEXT, metric_value TEXT)`,
		`INSERT INTO metrics VALUES (1, 'requests_total', '100')`,
		`CREATE TABLE preferences (owner TEXT, theme TEXT)`,
		`INSERT INTO preferences VALUES ('alice', 'light')`,
	})

	inspector := New(Options{Enabled: true})
	matches := inspector.InspectContent(Candidate{
		FilePath:  "Temp/cache.db",
		Name:      "cache.db",
		Extension: ".db",
		Size:      int64(len(content)),
	}, content)
	if len(matches) != 0 {
		t.Fatalf("expected benign sqlite to stay quiet, got %#v", matches)
	}
}

func buildSQLiteFixture(t *testing.T, statements []string) []byte {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "snablr-sqliteinspect-*.db")
	if err != nil {
		t.Fatalf("CreateTemp returned error: %v", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite3", tmpPath)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	defer db.Close()

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("Exec(%q) returned error: %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	return content
}

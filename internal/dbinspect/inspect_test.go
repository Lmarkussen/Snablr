package dbinspect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectorFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fixture   string
		expectIDs []string
	}{
		{
			name:      "validated mssql connection string",
			fixture:   "mssql-connection-string.config",
			expectIDs: []string{"dbinspect.access.connection_string"},
		},
		{
			name:      "validated odbc dsn with credentials",
			fixture:   "odbc.ini",
			expectIDs: []string{"dbinspect.artifact.odbc_ini", "dbinspect.access.dsn"},
		},
		{
			name:      "validated oracle tns service",
			fixture:   "tnsnames.ora",
			expectIDs: []string{"dbinspect.artifact.oracle_tnsnames", "dbinspect.infrastructure.oracle_tns"},
		},
		{
			name:      "sqlite artifact",
			fixture:   "reporting.sqlite3",
			expectIDs: []string{"dbinspect.artifact.sqlite3_db"},
		},
		{
			name:      "database backup artifact",
			fixture:   "payroll-sql-backup.bak",
			expectIDs: []string{"dbinspect.artifact.database_backup"},
		},
		{
			name:      "validated sql dump structure",
			fixture:   "mysql-dump.sql",
			expectIDs: []string{"dbinspect.artifact.sql_dump_header", "dbinspect.artifact.sql_dump_structure"},
		},
		{
			name:      "benign database notes stay quiet",
			fixture:   "benign-database-notes.txt",
			expectIDs: nil,
		},
		{
			name:      "placeholder jdbc example stays quiet",
			fixture:   "jdbc-placeholder.txt",
			expectIDs: nil,
		},
		{
			name:      "generic bak file stays quiet",
			fixture:   "meeting-notes.bak",
			expectIDs: nil,
		},
		{
			name:      "migration sql stays quiet",
			fixture:   "migration-script.sql",
			expectIDs: nil,
		},
	}

	inspector := New()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			candidate, content := loadFixtureCandidate(t, tt.fixture)
			matches := append(inspector.InspectMetadata(candidate), inspector.InspectContent(candidate, content)...)

			if len(tt.expectIDs) == 0 {
				if len(matches) != 0 {
					t.Fatalf("expected no matches for %s, got %#v", tt.fixture, matches)
				}
				return
			}

			got := make(map[string]struct{}, len(matches))
			for _, match := range matches {
				got[match.ID] = struct{}{}
			}
			for _, expected := range tt.expectIDs {
				if _, ok := got[expected]; !ok {
					t.Fatalf("expected match %q for %s, got %#v", expected, tt.fixture, matches)
				}
			}
		})
	}
}

func loadFixtureCandidate(t *testing.T, name string) (Candidate, []byte) {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "rules", "fixtures", "database", name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat fixture %s: %v", path, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	return Candidate{
		FilePath:  path,
		Name:      filepath.Base(path),
		Extension: filepath.Ext(path),
		Size:      info.Size(),
	}, content
}

func TestInspectorConnectionCredentialRepresentations(t *testing.T) {
	inspector := New()
	candidate := Candidate{Name: "connections.conf", Extension: ".conf", FilePath: "connections.conf"}
	tests := []struct {
		name string
		text string
		want string
	}{
		{"quoted semicolon", `Server=db-synthetic;Database=app;User ID=svc-r4c4;Password="Synthetic;Pass=482!";`, "dbinspect.access.connection_string"},
		{"braced odbc", `Driver={PostgreSQL Unicode};Server=db-synthetic;UID=svc-r4c4;PWD={P@ss;word!};`, "dbinspect.access.connection_string"},
		{"postgres keyword value", `host='db synthetic' dbname=app user=svc-r4c4 password='R4C4 Password 482!'`, "dbinspect.access.connection_string"},
		{"postgres url", `postgresql://svc-r4c4:R4C4%20Password%20482%21@db-synthetic:5432/app`, "dbinspect.access.connection_string"},
		{"mariadb url", `mariadb://svc-r4c4:SyntheticPass482%21@db-synthetic/app`, "dbinspect.access.connection_string"},
		{"sqlserver url", `sqlserver://svc-r4c4:SyntheticPass483%21@db-synthetic/app`, "dbinspect.access.connection_string"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := inspector.InspectContent(candidate, []byte(test.text))
			found := false
			for _, match := range matches {
				if match.ID == test.want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected %s in %#v", test.want, matches)
			}
		})
	}
}

func TestInspectorConnectionCredentialNegatives(t *testing.T) {
	inspector := New()
	candidate := Candidate{Name: "connections.conf", Extension: ".conf", FilePath: "connections.conf"}
	for _, text := range []string{
		`Server=db-synthetic;User ID=svc-r4c4;Integrated Security=true;`,
		`postgresql://svc-r4c4@db-synthetic/app`,
		`postgresql://svc-r4c4:${DB_PASSWORD}@db-synthetic/app`,
		`Server=db-synthetic;User ID=svc-r4c4;Password=********;`,
	} {
		for _, match := range inspector.InspectContent(candidate, []byte(text)) {
			if match.ID == "dbinspect.access.connection_string" {
				t.Fatalf("unexpected credential match for %q: %#v", text, match)
			}
		}
	}
}

func TestInspectorScopedDatabaseFieldsPairWithinNamespace(t *testing.T) {
	candidate := Candidate{Name: "database.properties", Extension: ".properties", FilePath: "database/database.properties"}
	matches := New().InspectContent(candidate, []byte("datasource.primary.username=svc-primary\ndatasource.primary.password=R4C4-Primary!\ndatasource.backup.username=svc-backup\ndatasource.backup.password=R4C4-Backup!\n"))
	count := 0
	for _, match := range matches {
		if match.ID == "dbinspect.access.connection_string" {
			count++
			if !strings.Contains(match.MatchedText, "svc-") || !strings.Contains(match.MatchedText, "password=") {
				t.Fatalf("scoped match lost canonical values: %#v", match)
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected two scoped database matches, got %d (%#v)", count, matches)
	}
}

func TestInspectorScopedDatabaseFieldsRejectUnrelatedSecrets(t *testing.T) {
	candidate := Candidate{Name: "database.env", Extension: ".env", FilePath: "database/database.env"}
	matches := New().InspectContent(candidate, []byte("API_USER=svc-api\nAPI_SECRET=R4C4-Token!\nusername=svc-unrelated\npassword=R4C4-Password!\n"))
	for _, match := range matches {
		if match.ID == "dbinspect.access.connection_string" {
			t.Fatalf("unrelated fields were paired: %#v", match)
		}
	}
}

func TestInspectorNorwegianConnectionAliases(t *testing.T) {
	candidate := Candidate{Name: "database-norsk.conf", Extension: ".conf", FilePath: "database/database-norsk.conf"}
	matches := New().InspectContent(candidate, []byte("Server=norsk-db;Database=app;brukernavn=bruker-æ;passord=Passord-øå!;"))
	for _, match := range matches {
		if match.ID == "dbinspect.access.connection_string" {
			return
		}
	}
	t.Fatalf("Norwegian connection aliases were not recognized: %#v", matches)
}

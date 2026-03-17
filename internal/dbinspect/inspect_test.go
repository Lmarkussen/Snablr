package dbinspect

import (
	"os"
	"path/filepath"
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

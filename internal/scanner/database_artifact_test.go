package scanner

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/sqliteinspect"
	"snablr/pkg/logx"
)

type databaseArtifactTestSink struct {
	findings   []Finding
	candidates []credentialanalysis.Candidate
}

func (s *databaseArtifactTestSink) WriteFinding(f Finding) error {
	s.findings = append(s.findings, f)
	return nil
}

func (s *databaseArtifactTestSink) Close() error { return nil }

func (s *databaseArtifactTestSink) RecordCredentialCandidate(c credentialanalysis.Candidate) error {
	s.candidates = append(s.candidates, c)
	return nil
}

func loadDatabaseArtifactTestManager(t *testing.T) *rules.Manager {
	t.Helper()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	return manager
}

func isDatabaseArtifactRuleID(ruleID string) bool {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	return ruleID == "extension.database_and_backup_extensions" ||
		strings.HasPrefix(ruleID, "dbinspect.artifact.")
}

func hasDatabaseArtifactFinding(findings []Finding, path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, finding := range findings {
		if !isDatabaseArtifactRuleID(finding.RuleID) {
			continue
		}
		if path == "" || strings.ToLower(strings.TrimSpace(finding.FilePath)) == path {
			return true
		}
	}
	return false
}

func TestDatabaseArtifactFindingsAreEmittedFromMetadataWithoutContent(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))

	tests := []struct {
		name string
		path string
	}{
		{name: "generic db", path: "Apps/application.db"},
		{name: "sqlite", path: "Apps/broken.sqlite"},
		{name: "sqlite3", path: "Apps/reporting.sqlite3"},
		{name: "db3", path: "Apps/records.db3"},
		{name: "access mdb", path: "Apps/inventory.mdb"},
		{name: "access accdb", path: "Apps/operations.accdb"},
		{name: "mssql data", path: "Data/application.mdf"},
		{name: "mssql secondary data", path: "Data/application.ndf"},
		{name: "mssql log", path: "Data/application.ldf"},
		{name: "dbase", path: "Data/legacy.dbf"},
		{name: "firebird", path: "Data/legacy.fdb"},
		{name: "bacpac", path: "Data/export.bacpac"},
		{name: "dacpac", path: "Data/export.dacpac"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			meta := FileMetadata{
				Host:      "fs01",
				Share:     "Apps",
				FilePath:  tt.path,
				Name:      filepath.Base(tt.path),
				Extension: filepath.Ext(tt.path),
				Size:      256,
			}
			evaluation := engine.Evaluate(meta, nil)
			if !hasDatabaseArtifactFinding(evaluation.Findings, tt.path) {
				t.Fatalf("expected database artifact finding for %s, got %#v", tt.path, evaluation.Findings)
			}
		})
	}
}

func TestDatabaseArtifactFindingReadableSQLiteAndCredentialExtraction(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'Synthet!cPass2025')`,
	})

	sink := &databaseArtifactTestSink{}
	engine := NewEngine(Options{
		SQLite: sqliteinspect.Options{
			Enabled:            true,
			AutoDBMaxSize:      1 << 20,
			MaxDBSize:          1 << 20,
			MaxTables:          8,
			MaxRowsPerTable:    5,
			MaxCellBytes:       256,
			MaxTotalBytes:      16 * 1024,
			MaxInterestingCols: 4,
		},
	}, manager, sink, logx.New("error"))
	engine.SetCredentialCandidateSink(sink)

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Apps",
		FilePath:  "Apps/records.db",
		Name:      "records.db",
		Extension: ".db",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if !hasDatabaseArtifactFinding(evaluation.Findings, "Apps/records.db") {
		t.Fatalf("expected database artifact finding for readable SQLite, got %#v", evaluation.Findings)
	}

	foundCredential := false
	for _, finding := range evaluation.Findings {
		if finding.DatabaseTable == "users" && finding.DatabaseColumn == "password" {
			foundCredential = true
		}
	}
	if !foundCredential {
		t.Fatalf("expected SQLite credential finding, got %#v", evaluation.Findings)
	}
	if len(sink.candidates) == 0 {
		t.Fatalf("expected SQLite credential candidate to reach candidate sink, got none")
	}
}

func TestDatabaseArtifactFindingInvalidSQLiteDoesNotInventCredentials(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	content := []byte("this is not a sqlite database header or valid content")

	sink := &databaseArtifactTestSink{}
	engine := NewEngine(Options{
		SQLite: sqliteinspect.Options{
			Enabled:            true,
			AutoDBMaxSize:      1 << 20,
			MaxDBSize:          1 << 20,
			MaxTables:          8,
			MaxRowsPerTable:    5,
			MaxCellBytes:       256,
			MaxTotalBytes:      16 * 1024,
			MaxInterestingCols: 4,
		},
	}, manager, sink, logx.New("error"))
	engine.SetCredentialCandidateSink(sink)

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Apps",
		FilePath:  "Apps/broken.sqlite",
		Name:      "broken.sqlite",
		Extension: ".sqlite",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if !hasDatabaseArtifactFinding(evaluation.Findings, "Apps/broken.sqlite") {
		t.Fatalf("expected database artifact finding for invalid SQLite, got %#v", evaluation.Findings)
	}
	for _, finding := range evaluation.Findings {
		if finding.DatabaseTable != "" || finding.DatabaseColumn != "" {
			t.Fatalf("invalid SQLite produced a content-backed credential finding: %#v", finding)
		}
	}
	if len(sink.candidates) != 0 {
		t.Fatalf("invalid SQLite produced credential candidates: %#v", sink.candidates)
	}
}

func TestDatabaseArtifactFindingSurvivesOversizedFileSkip(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	engine := NewEngine(Options{MaxFileSizeBytes: 64}, manager, nil, logx.New("error"))

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Data",
		FilePath:  "Data/application.mdf",
		Name:      "application.mdf",
		Extension: ".mdf",
		Size:      4096,
	}

	evaluation := engine.Evaluate(meta, nil)
	if !hasDatabaseArtifactFinding(evaluation.Findings, "Data/application.mdf") {
		t.Fatalf("expected oversized database artifact to remain visible, got %#v", evaluation.Findings)
	}
	if !evaluation.Skipped {
		t.Fatalf("expected oversized database to remain marked skipped for content inspection")
	}
}

func TestDatabaseArtifactFindingSurvivesReadFailureThroughScannerFlow(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	sink := &databaseArtifactTestSink{}
	engine := NewEngine(Options{
		SQLite: sqliteinspect.Options{
			Enabled:            true,
			AutoDBMaxSize:      1 << 20,
			MaxDBSize:          1 << 20,
			MaxTables:          8,
			MaxRowsPerTable:    5,
			MaxCellBytes:       256,
			MaxTotalBytes:      16 * 1024,
			MaxInterestingCols: 4,
		},
	}, manager, sink, logx.New("error"))
	engine.SetCredentialCandidateSink(sink)

	job := Job{
		Metadata: FileMetadata{
			Host:      "fs01",
			Share:     "Apps",
			FilePath:  "Apps/finance.sqlite",
			Name:      "finance.sqlite",
			Extension: ".sqlite",
			Size:      128,
		},
		LoadContent: func(context.Context, FileMetadata) ([]byte, error) {
			return nil, errors.New("simulated content read failure")
		},
	}

	pool := NewWorkerPool(engine, sink, logx.New("error"), nil, 1)
	if err := pool.Scan(context.Background(), jobsWithSingle(job)); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if !hasDatabaseArtifactFinding(sink.findings, "Apps/finance.sqlite") {
		t.Fatalf("expected database artifact finding to survive read failure, got %#v", sink.findings)
	}
	for _, finding := range sink.findings {
		if finding.DatabaseTable != "" || finding.DatabaseColumn != "" {
			t.Fatalf("read failure produced a content-backed credential finding: %#v", finding)
		}
	}
	if len(sink.candidates) != 0 {
		t.Fatalf("read failure produced credential candidates: %#v", sink.candidates)
	}
}

func TestBenignDatabaseLikeNamesDoNotBecomeDatabaseArtifacts(t *testing.T) {
	t.Parallel()

	manager := loadDatabaseArtifactTestManager(t)
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))

	tests := []struct {
		name    string
		path    string
		content string
	}{
		{name: "database notes", path: "Notes/database-notes.txt", content: "database notes only"},
		{name: "adb tool", path: "Notes/adb-tool.txt", content: "adb tool notes"},
		{name: "db config", path: "Configs/db-config.yaml", content: "app: demo\n"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			meta := FileMetadata{
				Host:      "fs01",
				Share:     "Share",
				FilePath:  tt.path,
				Name:      filepath.Base(tt.path),
				Extension: filepath.Ext(tt.path),
				Size:      int64(len(tt.content)),
			}
			evaluation := engine.Evaluate(meta, []byte(tt.content))
			if hasDatabaseArtifactFinding(evaluation.Findings, tt.path) {
				t.Fatalf("benign file %s became a database artifact finding: %#v", tt.path, evaluation.Findings)
			}
		})
	}
}

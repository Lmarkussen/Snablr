package output

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

type sqlRegressionSink struct {
	findings   []scanner.Finding
	candidates []credentialanalysis.Candidate
}

func (s *sqlRegressionSink) WriteFinding(f scanner.Finding) error {
	s.findings = append(s.findings, f)
	return nil
}

func (s *sqlRegressionSink) Close() error { return nil }

func (s *sqlRegressionSink) RecordCredentialCandidate(c credentialanalysis.Candidate) error {
	s.candidates = append(s.candidates, c)
	return nil
}

func loadSQLRegressionManager(t *testing.T) *rules.Manager {
	t.Helper()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	return manager
}

func evaluateSQLRegressionFile(t *testing.T, manager *rules.Manager, name, content string) ([]scanner.Finding, []credentialanalysis.Candidate) {
	t.Helper()
	sink := &sqlRegressionSink{}
	engine := scanner.NewEngine(scanner.Options{}, manager, sink, logx.New("error"))
	engine.SetCredentialCandidateSink(sink)

	meta := scanner.FileMetadata{
		FilePath:  name,
		Name:      name,
		Extension: strings.ToLower(filepath.Ext(name)),
		Size:      int64(len(content)),
	}
	evaluation := engine.EvaluateContext(context.Background(), meta, []byte(content))
	return evaluation.Findings, sink.candidates
}

func findingByRule(findings []scanner.Finding, ruleID string) *scanner.Finding {
	for index := range findings {
		if strings.EqualFold(findings[index].RuleID, ruleID) {
			return &findings[index]
		}
	}
	return nil
}

func TestSQLAndCredentialFalsePositivesDoNotReachHTML(t *testing.T) {
	t.Parallel()

	manager := loadSQLRegressionManager(t)

	ddlOnly := "CREATE TABLE users (id int, name varchar(64));\n" +
		"ALTER TABLE users ADD COLUMN created_at timestamp;\n" +
		"CREATE INDEX idx_users_name ON users (name);\n"
	ddlFindings, _ := evaluateSQLRegressionFile(t, manager, "schema.sql", ddlOnly)
	if dump := findingByRule(ddlFindings, "dbinspect.artifact.sql_dump_structure"); dump != nil {
		t.Fatalf("DDL-only SQL classified as dump: %#v", dump)
	}
	if script := findingByRule(ddlFindings, "dbinspect.artifact.sql_script"); script == nil || !strings.EqualFold(script.Severity, "low") {
		t.Fatalf("DDL-only SQL did not produce a low script artifact: %#v", ddlFindings)
	}

	var dumpBuilder strings.Builder
	dumpBuilder.WriteString("CREATE TABLE export (id int, name varchar(64));\n")
	for index := 0; index < 250; index++ {
		dumpBuilder.WriteString("INSERT INTO export (id, name) VALUES (")
		dumpBuilder.WriteString(itoaTest(index))
		dumpBuilder.WriteString(", 'row-")
		dumpBuilder.WriteString(itoaTest(index))
		dumpBuilder.WriteString("');\n")
	}
	dumpFindings, _ := evaluateSQLRegressionFile(t, manager, "export.sql", dumpBuilder.String())
	if findingByRule(dumpFindings, "dbinspect.artifact.sql_dump_structure") == nil {
		t.Fatalf("large literal data export was not classified as a dump: %#v", dumpFindings)
	}

	bogusSQL := "SET @counter = 1;\n" +
		"Password=@var\n" +
		"Password=@bind_value\n" +
		"Password=func(column_a, 1, 2)\n" +
		"Password=value and\n" +
		"PASSWORD=field,,type(255)\n" +
		"Password=plain words here\n"
	_, bogusCandidates := evaluateSQLRegressionFile(t, manager, "install.sql", bogusSQL)
	if len(bogusCandidates) != 0 {
		t.Fatalf("bogus SQL fragments became credential candidates: %#v", bogusCandidates)
	}

	genuine := "AdminPassword=Synthetic-Admin-123!\n" +
		"$SvcPass = \"Synthetic-Service-123!\"\n" +
		"export RUN_PASSWORD=Synthetic-Run-123!\n"
	_, genuineCandidates := evaluateSQLRegressionFile(t, manager, "deploy.ps1", genuine)
	genuineValues := map[string]bool{}
	for _, candidate := range genuineCandidates {
		genuineValues[candidate.Value] = true
	}
	for _, want := range []string{"Synthetic-Admin-123!", "Synthetic-Service-123!", "Synthetic-Run-123!"} {
		if !genuineValues[want] {
			t.Fatalf("genuine credential %q was not retained: %#v", want, genuineCandidates)
		}
	}

	// Generic database file visibility must be preserved: the extension
	// artifact is produced from metadata even without content.
	artifactFindings, _ := evaluateSQLRegressionFile(t, manager, "reporting.sqlite3", "")
	if findingByRule(artifactFindings, "dbinspect.artifact.sqlite3_db") == nil {
		t.Fatalf("database artifact visibility was lost: %#v", artifactFindings)
	}

	// Render the safe HTML report from the same findings and candidates and
	// confirm the triage outcome.
	var htmlBuf strings.Builder
	htmlWriter, err := NewHTMLWriter(&htmlBuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range append(append([]scanner.Finding{}, ddlFindings...), dumpFindings...) {
		if err := htmlWriter.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	for _, finding := range artifactFindings {
		if err := htmlWriter.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range bogusCandidates {
		if err := htmlWriter.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range genuineCandidates {
		if err := htmlWriter.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := htmlWriter.Close(); err != nil {
		t.Fatal(err)
	}
	htmlOut := htmlBuf.String()

	if !strings.Contains(htmlOut, "Likely SQL Data Dump Or Export") {
		t.Fatalf("real data export was not visible in HTML")
	}
	if !strings.Contains(htmlOut, "SQL Script Or Schema Artifact") {
		t.Fatalf("schema script artifact was not visible in HTML")
	}
	for _, bogus := range []string{"@var", "@bind_value", "func(column_a"} {
		if strings.Contains(htmlOut, bogus) {
			t.Fatalf("bogus SQL fragment %q leaked into HTML", bogus)
		}
	}

	// The credential export must retain genuine credentials and drop fragments.
	var credsBuf strings.Builder
	credsWriter := NewCredsWriter(&credsBuf, nil)
	for _, candidate := range append(append([]credentialanalysis.Candidate{}, bogusCandidates...), genuineCandidates...) {
		if err := credsWriter.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := credsWriter.Close(); err != nil {
		t.Fatal(err)
	}
	credsOut := credsBuf.String()
	if !strings.Contains(credsOut, "Synthetic-Admin-123!") {
		t.Fatalf("genuine credential missing from creds export:\n%s", credsOut)
	}
	for _, bogus := range []string{"@var", "@bind_value", "field,,type"} {
		if strings.Contains(credsOut, bogus) {
			t.Fatalf("bogus fragment %q leaked into creds export", bogus)
		}
	}
}

func itoaTest(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

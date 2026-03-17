package scanner

import (
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/dbinspect"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestEngineNeedsContentUsesRuleExtensionHints(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "testdata", "rules", "unit")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))

	if engine.NeedsContent(FileMetadata{
		FilePath:  "images/logo.jpg",
		Name:      "logo.jpg",
		Extension: ".jpg",
		Size:      128,
	}) {
		t.Fatal("expected .jpg file to skip content reads when no content rule targets that extension")
	}

	if !engine.NeedsContent(FileMetadata{
		FilePath:  "configs/app.conf",
		Name:      "app.conf",
		Extension: ".conf",
		Size:      128,
	}) {
		t.Fatal("expected .conf file to require content reads when content rule targets that extension")
	}
}

func TestCorrelateFindingsGroupsSignalsByFileAndCategory(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{
		Host:                "fs01",
		Share:               "Finance",
		FilePath:            "Finance/app.env",
		Name:                "app.env",
		Extension:           ".env",
		Priority:            92,
		PriorityReason:      "high-value path",
		SharePriority:       85,
		SharePriorityReason: "sensitive share",
	}

	filenameRule := rules.Rule{
		ID:          "filename.credentials_hint",
		Name:        "Credentials Hint",
		Description: "Find credential-oriented filenames.",
		Type:        rules.RuleTypeFilename,
		Severity:    rules.SeverityMedium,
		Confidence:  rules.ConfidenceLow,
		Category:    "credentials",
	}
	contentRule := rules.Rule{
		ID:          "content.inline_password",
		Name:        "Inline Password",
		Description: "Detect password assignments.",
		Type:        rules.RuleTypeContent,
		Severity:    rules.SeverityHigh,
		Confidence:  rules.ConfidenceMedium,
		Category:    "credentials",
	}

	correlated := correlateFindings(meta, []Finding{
		newFinding(filenameRule, meta, heuristicEvidence(filenameRule.Type, "app.env")),
		newFinding(contentRule, meta, findingEvidence{
			SignalType:          "content",
			Match:               "password=Winter2025!",
			MatchedText:         "password=Winter2025!",
			MatchedTextRedacted: "password=********",
			Snippet:             "password=********",
			Context:             "password=Winter2025!",
			ContextRedacted:     "password=********",
			PotentialAccount:    "user=demo",
			LineNumber:          1,
		}),
	})

	if len(correlated) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(correlated))
	}
	if len(correlated[0].MatchedRuleIDs) != 2 {
		t.Fatalf("expected two matched rules, got %#v", correlated[0].MatchedRuleIDs)
	}
	if len(correlated[0].MatchedSignalTypes) < 3 {
		t.Fatalf("expected multiple signal types, got %#v", correlated[0].MatchedSignalTypes)
	}
	if correlated[0].ConfidenceScore < 70 || correlated[0].Confidence != "high" {
		t.Fatalf("expected elevated confidence, got score=%d level=%s", correlated[0].ConfidenceScore, correlated[0].Confidence)
	}
	if len(correlated[0].SupportingSignals) < 4 {
		t.Fatalf("expected supporting signals to include contextual boosts, got %#v", correlated[0].SupportingSignals)
	}
	if correlated[0].ConfidenceBreakdown.BaseScore == 0 || correlated[0].ConfidenceBreakdown.ContentSignalStrength == 0 || correlated[0].ConfidenceBreakdown.CorrelationContribution == 0 || correlated[0].ConfidenceBreakdown.PathContextContribution == 0 {
		t.Fatalf("expected structured confidence breakdown, got %#v", correlated[0].ConfidenceBreakdown)
	}
	if correlated[0].ConfidenceBreakdown.ValueQualityScore == 0 || correlated[0].ConfidenceBreakdown.FinalScore != correlated[0].ConfidenceScore {
		t.Fatalf("expected value quality and final score in breakdown, got %#v", correlated[0].ConfidenceBreakdown)
	}
}

func TestEngineNeedsContentForDatabaseArtifactsWithoutRules(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))

	if !engine.NeedsContent(FileMetadata{
		FilePath:  "Configs/app.dsn",
		Name:      "app.dsn",
		Extension: ".dsn",
		Size:      256,
	}) {
		t.Fatal("expected DB inspector to request content for .dsn artifacts")
	}
}

func TestEngineEvaluateIncludesDatabaseInspectionFindings(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Configs",
		FilePath:  "Configs/app.dsn",
		Name:      "app.dsn",
		Extension: ".dsn",
		Size:      256,
		Priority:  65,
	}
	content := []byte("DSN=Payroll;Driver=ODBC Driver 18 for SQL Server;Server=sql01.example.local;Database=Payroll;UID=svc_payroll;PWD=Winter2025!")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) != 2 {
		t.Fatalf("expected exactly 2 DB inspection findings, got %#v", evaluation.Findings)
	}

	var foundAccess bool
	var foundArtifact bool
	for _, finding := range evaluation.Findings {
		switch finding.Category {
		case "database-access":
			foundAccess = true
			if finding.SignalType != "validated" {
				t.Fatalf("expected validated signal type, got %#v", finding)
			}
			if finding.Confidence != "high" {
				t.Fatalf("expected high confidence database access finding, got %#v", finding)
			}
		case "database-artifacts":
			foundArtifact = true
			if finding.Confidence != "medium" {
				t.Fatalf("expected artifact-only finding to stay medium confidence, got %#v", finding)
			}
		}
	}
	if !foundAccess {
		t.Fatalf("expected database-access finding, got %#v", evaluation.Findings)
	}
	if !foundArtifact {
		t.Fatalf("expected database-artifacts finding, got %#v", evaluation.Findings)
	}
}

func TestCorrelateFindingsDatabaseArtifactAloneStaysMediumConfidence(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Archive",
		FilePath:  "Archive/reporting.sqlite3",
		Name:      "reporting.sqlite3",
		Extension: ".sqlite3",
		Size:      256,
	}
	artifactMatches := dbinspect.New().InspectMetadata(dbinspect.Candidate{
		FilePath:  meta.FilePath,
		Name:      meta.Name,
		Extension: meta.Extension,
		Size:      meta.Size,
	})

	findings := correlateFindings(meta, findingsFromDBMatches(meta, artifactMatches))
	if len(findings) != 1 {
		t.Fatalf("expected 1 correlated finding, got %#v", findings)
	}
	if findings[0].Category != "database-artifacts" {
		t.Fatalf("unexpected category: %#v", findings[0])
	}
	if findings[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence for artifact-only finding, got %#v", findings[0])
	}
}

func TestEngineEvaluatePromotesValidatedSQLDump(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Backups",
		FilePath:  "Backups/prod/schema-export.sql",
		Name:      "schema-export.sql",
		Extension: ".sql",
		Size:      1024,
		Priority:  82,
	}
	content := []byte("-- MySQL dump 10.13  Distrib 8.0.36\nDROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (id int);\nLOCK TABLES `users` WRITE;\nINSERT INTO `users` VALUES (1);\nINSERT INTO `users` VALUES (2);\nUNLOCK TABLES;\n")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one correlated SQL dump finding, got %#v", evaluation.Findings)
	}

	finding := evaluation.Findings[0]
	if finding.Category != "database-artifacts" {
		t.Fatalf("expected database-artifacts category, got %#v", finding)
	}
	if !finding.Actionable || finding.TriageClass != "actionable" {
		t.Fatalf("expected actionable dump finding, got %#v", finding)
	}
	if finding.Confidence != "high" || finding.ConfidenceScore < 70 {
		t.Fatalf("expected promoted high-confidence dump finding, got %#v", finding)
	}
	if !hasTag(finding.Tags, "db:type:dump-export") {
		t.Fatalf("expected dump-export tag, got %#v", finding.Tags)
	}
}

func TestEngineEvaluateKeepsGenericSQLQuiet(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Deploy/migration-script.sql",
		Name:      "migration-script.sql",
		Extension: ".sql",
		Size:      256,
	}
	content := []byte("ALTER TABLE users ADD COLUMN last_login timestamp;\nCREATE INDEX idx_users_last_login ON users (last_login);\n")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) != 0 {
		t.Fatalf("expected generic migration SQL to stay quiet, got %#v", evaluation.Findings)
	}
}

func TestCorrelateFindingsConfigOnlyStaysLowVisibility(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Apps",
		FilePath:  "Apps/appsettings.json",
		Name:      "appsettings.json",
		Extension: ".json",
		Size:      128,
		Priority:  65,
	}
	rule := rules.Rule{
		ID:          "filename.sensitive_config_names",
		Name:        "Sensitive Config Names",
		Description: "Detect common config filenames that frequently contain environment settings or embedded secrets.",
		Type:        rules.RuleTypeFilename,
		Severity:    rules.SeverityHigh,
		Confidence:  rules.ConfidenceHigh,
		Category:    "configuration",
	}

	findings := correlateFindings(meta, []Finding{
		newFinding(rule, meta, heuristicEvidence(rule.Type, meta.Name)),
	})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if findings[0].TriageClass != "config-only" || findings[0].Actionable {
		t.Fatalf("expected config-only classification, got %#v", findings[0])
	}
	if findings[0].Severity != "low" || findings[0].Confidence != "low" {
		t.Fatalf("expected low-visibility config-only finding, got %#v", findings[0])
	}
	if findings[0].ConfidenceBreakdown.HeuristicSignalContribution == 0 || findings[0].ConfidenceBreakdown.FinalScore != findings[0].ConfidenceScore {
		t.Fatalf("expected consistent confidence breakdown, got %#v", findings[0].ConfidenceBreakdown)
	}
}

func TestEngineEvaluatePromotesSecretStoreArtifactFinding(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Archive",
		FilePath:  "Archive/NTDS.DIT",
		Name:      "NTDS.DIT",
		Extension: "",
		Size:      4096,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one secret-store finding, got %#v", evaluation.Findings)
	}

	finding := evaluation.Findings[0]
	if finding.RuleID != "filename.secret_store_artifacts" {
		t.Fatalf("expected secret-store rule, got %#v", finding)
	}
	if finding.TriageClass != "actionable" || !finding.Actionable {
		t.Fatalf("expected actionable secret-store finding, got %#v", finding)
	}
	if finding.Category != "credentials" || finding.Severity != "critical" {
		t.Fatalf("expected critical credentials finding, got %#v", finding)
	}
}

func TestEngineEvaluatePromotesWindowsHiveArtifactFinding(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Archive",
		FilePath:  "Archive/Windows/System32/config/SYSTEM",
		Name:      "SYSTEM",
		Extension: "",
		Size:      8192,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one Windows hive finding, got %#v", evaluation.Findings)
	}

	finding := evaluation.Findings[0]
	if finding.RuleID != "filename.windows_hive_artifacts" {
		t.Fatalf("expected Windows hive rule, got %#v", finding)
	}
	if finding.TriageClass != "actionable" || !finding.Actionable {
		t.Fatalf("expected actionable Windows hive finding, got %#v", finding)
	}
	if finding.Category != "credentials" || finding.Severity != "critical" {
		t.Fatalf("expected critical credentials finding, got %#v", finding)
	}
}

func TestEngineEvaluatePromotesSecretStoreBackupArtifactFinding(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Archive",
		FilePath:  "Archive/NTDS.DIT.bak",
		Name:      "NTDS.DIT.bak",
		Extension: ".bak",
		Size:      8192,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected secret-store backup findings, got %#v", evaluation.Findings)
	}

	found := false
	for _, finding := range evaluation.Findings {
		if finding.RuleID != "filename.ad_database_backup_artifacts" {
			continue
		}
		found = true
		if finding.TriageClass != "actionable" || !finding.Actionable {
			t.Fatalf("expected actionable secret-store backup finding, got %#v", finding)
		}
		if finding.Category != "credentials" || finding.Severity != "critical" {
			t.Fatalf("expected critical credentials finding, got %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected AD database backup rule in findings, got %#v", evaluation.Findings)
	}
}

func TestEngineSuppressesPlaceholderSecretAssignments(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Configs/appsettings.json",
		Name:      "appsettings.json",
		Extension: ".json",
		Size:      128,
	}
	content := []byte("client_secret=<secret>\npassword=changeme\n")

	evaluation := engine.Evaluate(meta, content)
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "content.secret_assignment_indicators" || finding.RuleID == "content.password_assignment_indicators" || finding.RuleID == "content.cloud_configuration_indicators" {
			t.Fatalf("expected placeholder-only secret indicators to be suppressed, got %#v", evaluation.Findings)
		}
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(tag), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func TestEngineSuppressesWeakSampleSecretAssignments(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Configs/app.env",
		Name:      "app.env",
		Extension: ".env",
		Size:      128,
	}
	content := []byte("db_password=test1234\nclient_secret=example123\n")

	evaluation := engine.Evaluate(meta, content)
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "content.secret_assignment_indicators" || finding.RuleID == "content.password_assignment_indicators" {
			t.Fatalf("expected weak sample secret indicators to be suppressed, got %#v", evaluation.Findings)
		}
	}
}

func TestCorrelateFindingsKeepsDatabaseCategoriesSeparate(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Configs",
		FilePath:  "Configs/app.dsn",
		Name:      "app.dsn",
		Extension: ".dsn",
		Size:      256,
		Priority:  65,
	}
	inspector := dbinspect.New()
	matches := append(
		inspector.InspectMetadata(dbinspect.Candidate{FilePath: meta.FilePath, Name: meta.Name, Extension: meta.Extension, Size: meta.Size}),
		inspector.InspectContent(dbinspect.Candidate{FilePath: meta.FilePath, Name: meta.Name, Extension: meta.Extension, Size: meta.Size}, []byte("DSN=Payroll;Driver=ODBC Driver 18 for SQL Server;Server=sql01.corp.local;Database=Payroll;UID=svc_payroll;PWD=Winter2025!"))...,
	)

	findings := correlateFindings(meta, findingsFromDBMatches(meta, matches))
	if len(findings) != 2 {
		t.Fatalf("expected separate findings for artifact and access categories, got %#v", findings)
	}
}

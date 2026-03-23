package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"snablr/internal/archiveinspect"
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

func TestEngineEvaluatesZIPArchivesWithinDefaultSizeLimit(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Public",
		FilePath:  "Public/loot.zip",
		Name:      "loot.zip",
		Extension: ".zip",
		Size:      2048,
	}
	content := buildZIPFixture(t, map[string][]byte{
		"configs/web.config": []byte("<configuration><appSettings><add key=\"password\" value=\"Winter2025!\" /></appSettings></configuration>"),
	})
	meta.Size = int64(len(content))

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected archive findings, got %#v", evaluation)
	}

	foundArchivePath := false
	for _, finding := range evaluation.Findings {
		if finding.ArchivePath != "Public/loot.zip" || finding.ArchiveMemberPath != "configs/web.config" || !finding.ArchiveLocalInspect {
			t.Fatalf("expected archive metadata on finding, got %#v", finding)
		}
		if finding.FilePath == "Public/loot.zip!configs/web.config" {
			foundArchivePath = true
		}
	}
	if !foundArchivePath {
		t.Fatalf("expected outer!inner archive path in findings, got %#v", evaluation.Findings)
	}
}

func TestEngineSkipsZIPArchivesLargerThanDefaultLimit(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Archive/large.zip",
		Name:      "large.zip",
		Extension: ".zip",
		Size:      10*1024*1024 + 1,
	}

	if engine.NeedsContent(meta) {
		t.Fatal("expected oversized zip to skip content reads by default")
	}

	evaluation := engine.Evaluate(meta, nil)
	if !evaluation.Skipped || !strings.Contains(evaluation.SkipReason, "automatic inspection limit") {
		t.Fatalf("expected automatic zip size skip, got %#v", evaluation)
	}
}

func TestEngineAllowsLargeZIPArchivesWhenConfigured(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{
		Archives: archiveOptionsForTests(func(opts *archiveinspect.Options) {
			opts.AllowLargeZIPs = true
			opts.MaxZIPSize = 32 * 1024 * 1024
		}),
	}, manager, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"dump.sql": []byte("-- MySQL dump 10.13\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\nINSERT INTO users VALUES (2);\nLOCK TABLES users WRITE;\nUNLOCK TABLES;\n"),
	})
	meta := FileMetadata{
		FilePath:  "Archive/large.zip",
		Name:      "large.zip",
		Extension: ".zip",
		Size:      12 * 1024 * 1024,
	}

	if !engine.NeedsContent(meta) {
		t.Fatal("expected explicit large zip override to require content")
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from explicitly allowed large zip, got %#v", evaluation)
	}
}

func TestEngineSkipsNonTextAndNestedArchiveMembers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	innerZIP := buildZIPFixture(t, map[string][]byte{
		"secret.txt": []byte("password=Winter2025!"),
	})
	content := buildZIPFixture(t, map[string][]byte{
		"image.png":             append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
		"nested/archive.zip":    innerZIP,
		"docs/readme.md":        []byte("just deployment notes"),
		"configs/settings.json": []byte("{\"db_password\":\"Winter2025!\"}"),
	})
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Archive/mixed.zip",
		Name:      "mixed.zip",
		Extension: ".zip",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	for _, finding := range evaluation.Findings {
		if strings.Contains(finding.FilePath, "image.png") || strings.Contains(finding.FilePath, "archive.zip") {
			t.Fatalf("expected non-text and nested archive members to be skipped, got %#v", evaluation.Findings)
		}
	}
}

func TestEngineHonorsArchiveInspectionLimits(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	content := buildZIPFixture(t, map[string][]byte{
		"one.env":   []byte("db_password=Winter2025!\n"),
		"two.env":   []byte("db_password=Winter2025!\n"),
		"three.env": []byte("db_password=Winter2025!\n"),
	})
	engine := NewEngine(Options{
		Archives: archiveOptionsForTests(func(opts *archiveinspect.Options) {
			opts.MaxMembers = 1
			opts.MaxTotalUncompressed = 64
		}),
	}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Archive/limited.zip",
		Name:      "limited.zip",
		Extension: ".zip",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected at least one finding, got %#v", evaluation)
	}
	for _, finding := range evaluation.Findings {
		if !strings.Contains(finding.FilePath, "one.env") {
			t.Fatalf("expected later archive members to stay unread after limits, got %#v", evaluation.Findings)
		}
	}
}

func TestWorkerPoolLoadsArchiveContentOnce(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, newCaptureFindingSink(), logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"configs/.env":       []byte("db_password=Winter2025!\n"),
		"configs/web.config": []byte("<configuration><appSettings><add key=\"password\" value=\"Winter2025!\" /></appSettings></configuration>"),
	})
	var loads int32
	job := Job{
		Metadata: FileMetadata{
			FilePath:  "Archive/loot.zip",
			Name:      "loot.zip",
			Extension: ".zip",
			Size:      int64(len(content)),
		},
		LoadContent: func(context.Context, FileMetadata) ([]byte, error) {
			atomic.AddInt32(&loads, 1)
			return content, nil
		},
	}

	pool := NewWorkerPool(engine, newCaptureFindingSink(), logx.New("error"), nil, 1)
	if err := pool.Scan(context.Background(), jobsWithSingle(job)); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Fatalf("expected outer archive to be loaded once, got %d", got)
	}
}

type captureFindingSink struct{}

func newCaptureFindingSink() *captureFindingSink {
	return &captureFindingSink{}
}

func (*captureFindingSink) WriteFinding(Finding) error { return nil }
func (*captureFindingSink) Close() error               { return nil }

func jobsWithSingle(job Job) <-chan Job {
	ch := make(chan Job, 1)
	ch <- job
	close(ch)
	return ch
}

func buildZIPFixture(t *testing.T, members map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range members {
		writer, err := zw.Create(name)
		if err != nil {
			t.Fatalf("Create(%s) returned error: %v", name, err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatalf("Write(%s) returned error: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	return buf.Bytes()
}

func archiveOptionsForTests(mutate func(*archiveinspect.Options)) archiveinspect.Options {
	opts := archiveinspect.Options{
		Enabled:                  true,
		AutoZIPMaxSize:           10 * 1024 * 1024,
		AllowLargeZIPs:           false,
		MaxZIPSize:               10 * 1024 * 1024,
		MaxMembers:               64,
		MaxMemberBytes:           512 * 1024,
		MaxTotalUncompressed:     4 * 1024 * 1024,
		InspectExtensionlessText: true,
	}
	if mutate != nil {
		mutate(&opts)
	}
	return opts
}

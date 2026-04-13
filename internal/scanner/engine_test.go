package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/archiveinspect"
	"snablr/internal/dbinspect"
	"snablr/internal/rules"
	"snablr/internal/sqliteinspect"
	"snablr/pkg/logx"
)

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

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

func TestEngineEvaluateRecognizesAWSCredentialBundle(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Users",
		FilePath:  "Users/Alice/.aws/credentials",
		Name:      "credentials",
		Extension: "",
		Size:      512,
	}
	content := []byte("[default]\naws_access_key_id=AKIAABCDEFGHIJKLMNOP\naws_secret_access_key=abcdEFGHijklMNOPqrstUVWXyz0123456789/+=A\naws_session_token=IQoJb3JpZ2luX2VjEKD//////////wEaCXVzLWVhc3QtMSJHMEUCIQDLABCD1234TOKEN5678VALUE90XYZ0ABCD\n")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected AWS findings, got %#v", evaluation.Findings)
	}

	var foundBundle bool
	for _, finding := range evaluation.Findings {
		if finding.RuleID != "awsinspect.content.credentials_bundle" {
			continue
		}
		foundBundle = true
		if finding.Category != "credentials" || !finding.Actionable {
			t.Fatalf("expected actionable AWS credential bundle, got %#v", finding)
		}
		if finding.Confidence != "high" {
			t.Fatalf("expected high confidence for AWS credential bundle, got %#v", finding)
		}
	}
	if !foundBundle {
		t.Fatalf("expected awsinspect.content.credentials_bundle in %#v", evaluation.Findings)
	}
}

func TestEngineEvaluateKeepsAWSConfigArtifactSupporting(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Users",
		FilePath:  "Users/Alice/.aws/config",
		Name:      "config",
		Extension: "",
		Size:      128,
	}
	content := []byte("[default]\nregion = eu-north-1\noutput = json\n")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected AWS config artifact finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "awsinspect.path.config" {
		t.Fatalf("expected config artifact rule, got %#v", finding)
	}
	if finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected supporting AWS config artifact, got %#v", finding)
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

func TestEngineEvaluateDetectsExtensionlessPrivateKeyArtifact(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Users",
		FilePath:  "Users/Alice/.ssh/id_rsa",
		Name:      "id_rsa",
		Extension: "",
		Size:      4096,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one private key artifact finding, got %#v", evaluation.Findings)
	}

	finding := evaluation.Findings[0]
	if finding.RuleID != "filename.private_key_artifacts" {
		t.Fatalf("expected private key artifact rule, got %#v", finding)
	}
	if finding.Category != "crypto" || finding.Severity != "critical" {
		t.Fatalf("expected critical crypto finding, got %#v", finding)
	}
	if finding.TriageClass != "actionable" || !finding.Actionable {
		t.Fatalf("expected actionable private key finding, got %#v", finding)
	}
}

func TestEngineEvaluateValidatesExtensionlessPrivateKeyHeader(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Users",
		FilePath:  "Users/Alice/.ssh/id_rsa",
		Name:      "id_rsa",
		Extension: "",
		Size:      4096,
	}
	content := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nLAB_ONLY_SYNTHETIC_PRIVATE_KEY\n-----END OPENSSH PRIVATE KEY-----\n")

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one correlated private key finding, got %#v", evaluation.Findings)
	}

	finding := evaluation.Findings[0]
	if finding.Confidence != "high" || finding.ConfidenceScore < 70 {
		t.Fatalf("expected high-confidence private key finding, got %#v", finding)
	}
	foundFilename := false
	foundValidated := false
	for _, ruleID := range finding.MatchedRuleIDs {
		if ruleID == "filename.private_key_artifacts" {
			foundFilename = true
		}
		if ruleID == "keyinspect.content.private_key_header" {
			foundValidated = true
		}
	}
	if !foundFilename || !foundValidated {
		t.Fatalf("expected filename and validated key matches, got %#v", finding.MatchedRuleIDs)
	}
	if !hasTag(finding.Tags, "validated:private-key-header") {
		t.Fatalf("expected validated private key tag, got %#v", finding.Tags)
	}
}

func TestEngineEvaluateDetectsClientAuthArtifacts(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	for _, meta := range []FileMetadata{
		{
			FilePath:  "VPN/branch-admin.ovpn",
			Name:      "branch-admin.ovpn",
			Extension: ".ovpn",
			Size:      1024,
		},
		{
			FilePath:  "Users/Alice/Documents/client-admin.ppk",
			Name:      "client-admin.ppk",
			Extension: ".ppk",
			Size:      1024,
		},
	} {
		evaluation := engine.Evaluate(meta, nil)
		if len(evaluation.Findings) != 1 {
			t.Fatalf("expected one client-auth finding for %s, got %#v", meta.FilePath, evaluation.Findings)
		}
		finding := evaluation.Findings[0]
		if finding.RuleID != "extension.client_auth_artifacts" {
			t.Fatalf("expected client-auth extension rule, got %#v", finding)
		}
		if finding.Category != "remote-access" || finding.TriageClass != triageWeakReview || finding.Actionable {
			t.Fatalf("expected client-auth extension artifact to stay review-only, got %#v", finding)
		}
	}
}

func TestSupportingSSHFilesStayLowerPriorityThanPrivateKeys(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	privateKey := engine.Evaluate(FileMetadata{
		FilePath:  "Users/Alice/.ssh/id_rsa",
		Name:      "id_rsa",
		Extension: "",
		Size:      1024,
	}, nil)
	support := engine.Evaluate(FileMetadata{
		FilePath:  "Users/Alice/.ssh/known_hosts",
		Name:      "known_hosts",
		Extension: "",
		Size:      1024,
	}, nil)

	if len(privateKey.Findings) != 1 || len(support.Findings) != 1 {
		t.Fatalf("expected single findings, got private=%#v support=%#v", privateKey.Findings, support.Findings)
	}
	if severityRank(privateKey.Findings[0].Severity) <= severityRank(support.Findings[0].Severity) {
		t.Fatalf("expected private key to rank above supporting SSH artifact, got private=%#v support=%#v", privateKey.Findings[0], support.Findings[0])
	}
}

func TestEngineEvaluateDetectsWindowsImageBackupPath(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Backups",
		FilePath:  `Backups\SystemState\WindowsImageBackup\DC01\Backup 2025-01-01\C\Windows\System32\config\SAM`,
		Name:      "SAM",
		Extension: "",
		Size:      2048,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one backup path finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "backupinspect.path.windowsimagebackup" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Category != "backup-exposure" || finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected backup family path to stay review-only without secret artifact evidence, got %#v", finding)
	}
	if !hasTag(finding.Tags, "artifact:backup-family") || !hasTag(finding.Tags, "backup-family:windowsimagebackup") {
		t.Fatalf("expected backup-family tags, got %#v", finding.Tags)
	}
}

func TestEngineEvaluateDetectsRegBackBackupVariant(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  `Archive/SystemCopies/Windows/System32/config/RegBack/SECURITY.old`,
		Name:      "SECURITY.old",
		Extension: ".old",
		Size:      2048,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one backup path finding, got %#v", evaluation.Findings)
	}
	if evaluation.Findings[0].RuleID != "backupinspect.path.regback" {
		t.Fatalf("unexpected finding: %#v", evaluation.Findings[0])
	}
}

func TestEngineEvaluateDetectsFirefoxCredentialStoreArtifact(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Profiles",
		FilePath:  `Users\Alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\logins.json`,
		Name:      "logins.json",
		Extension: ".json",
		Size:      512,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one browser credential-store finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "browsercredinspect.firefox.logins" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Category != "browser-credentials" || finding.TriageClass != "weak-review" || finding.Actionable {
		t.Fatalf("expected weak-review browser finding, got %#v", finding)
	}
}

func TestEngineEvaluateKeepsPFXExtensionReviewOnly(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Recovery/Certificates/corp-admin.pfx",
		Name:      "corp-admin.pfx",
		Extension: ".pfx",
		Size:      2048,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one certificate extension finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "extension.key_and_certificate_extensions" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected bare PKCS#12 extension hit to stay review-only, got %#v", finding)
	}
}

func TestEngineEvaluateKeepsAWSCredentialArtifactSupportingWithoutKeyMaterial(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath: "Users/Alice/.aws/credentials",
		Name:     "credentials",
		Size:     128,
	}

	evaluation := engine.Evaluate(meta, []byte("[default]\nregion=eu-north-1\n"))
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one AWS credentials artifact finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "awsinspect.path.credentials" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected path-only AWS credentials artifact to stay review-only, got %#v", finding)
	}
}

func TestEngineEvaluateKeepsCredentialFilenameKeywordReviewOnly(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Users/Alice/Desktop/passwords.txt",
		Name:      "passwords.txt",
		Extension: ".txt",
		Size:      256,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one filename keyword finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "filename.credentials_and_secrets_keywords" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected credential-style filename keyword to stay review-only, got %#v", finding)
	}
}

func TestEngineEvaluateDetectsChromiumCredentialStoreBackupVariant(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  `Archive/ProfileCopies/Bob/AppData/Local/Google/Chrome/User Data/Default/Login Data`,
		Name:      "Login Data",
		Extension: "",
		Size:      512,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one browser credential-store finding, got %#v", evaluation.Findings)
	}
	if evaluation.Findings[0].RuleID != "browsercredinspect.chromium.login_data" {
		t.Fatalf("unexpected finding: %#v", evaluation.Findings[0])
	}
}

func TestEngineEvaluateDetectsWindowsCredentialStorePath(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Profiles",
		FilePath:  `Users\Alice\AppData\Roaming\Microsoft\Credentials\A1B2C3D4`,
		Name:      "A1B2C3D4",
		Extension: "",
		Size:      256,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one windows credential-store finding, got %#v", evaluation.Findings)
	}
	finding := evaluation.Findings[0]
	if finding.RuleID != "wincredinspect.path.credentials" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Category != "windows-credentials" || finding.TriageClass != triageWeakReview || finding.Actionable {
		t.Fatalf("expected standalone Windows Credentials path to stay review-only, got %#v", finding)
	}
	if !hasTag(finding.Tags, "credstore:path-exact") || !hasTag(finding.Tags, "credstore:type:credentials") {
		t.Fatalf("expected credential-store tags, got %#v", finding.Tags)
	}
}

func TestEngineEvaluateDetectsWindowsCredentialStoreBackupVariant(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  `Archive/ProfileCopy/Bob/AppData/Local/Microsoft/Vault/0A1B2C3D/Policy.vpol`,
		Name:      "Policy.vpol",
		Extension: ".vpol",
		Size:      256,
	}

	evaluation := engine.Evaluate(meta, nil)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("expected one vault path finding, got %#v", evaluation.Findings)
	}
	if evaluation.Findings[0].RuleID != "wincredinspect.path.vault" {
		t.Fatalf("unexpected finding: %#v", evaluation.Findings[0])
	}
	if evaluation.Findings[0].TriageClass != triageWeakReview || evaluation.Findings[0].Actionable {
		t.Fatalf("expected standalone Windows Vault path to stay review-only, got %#v", evaluation.Findings[0])
	}
}

func TestEngineEvaluateDetectsSQLiteInspectionFinding(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'Synthet!cPass2025')`,
	})
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:      "fs01",
		Share:     "Apps",
		FilePath:  "Apps/finance.sqlite",
		Name:      "finance.sqlite",
		Extension: ".sqlite",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected sqlite findings, got %#v", evaluation)
	}

	found := false
	for _, finding := range evaluation.Findings {
		if finding.DatabaseTable == "users" && finding.DatabaseColumn == "password" {
			found = true
			if finding.FilePath != "Apps/finance.sqlite::users.password" {
				t.Fatalf("expected composite sqlite path, got %#v", finding)
			}
			if finding.DatabaseFilePath != "Apps/finance.sqlite" {
				t.Fatalf("expected database file path, got %#v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("expected sqlite password finding, got %#v", evaluation.Findings)
	}
}

func TestEngineEvaluateSkipsLargeSQLiteByDefault(t *testing.T) {
	t.Parallel()

	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'Synthet!cPass2025')`,
	})
	engine := NewEngine(Options{
		SQLite: sqliteinspect.Options{
			Enabled:       true,
			AutoDBMaxSize: 64,
			MaxDBSize:     64,
		},
	}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Apps/finance.sqlite",
		Name:      "finance.sqlite",
		Extension: ".sqlite",
		Size:      4096,
	}

	evaluation := engine.Evaluate(meta, content)
	if !evaluation.Skipped || !strings.Contains(evaluation.SkipReason, "automatic inspection limit") {
		t.Fatalf("expected oversized sqlite to skip by default, got %#v", evaluation)
	}
}

func TestEngineEvaluateAllowsConfiguredLargeSQLite(t *testing.T) {
	t.Parallel()

	content := buildSQLiteDBFixture(t, []string{
		`CREATE TABLE users (id INTEGER, username TEXT, password TEXT)`,
		`INSERT INTO users VALUES (1, 'svc_finance', 'Synthet!cPass2025')`,
	})
	engine := NewEngine(Options{
		SQLite: sqliteinspect.Options{
			Enabled:         true,
			AutoDBMaxSize:   64,
			AllowLargeDBs:   true,
			MaxDBSize:       8192,
			MaxRowsPerTable: 2,
		},
	}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Apps/finance.sqlite",
		Name:      "finance.sqlite",
		Extension: ".sqlite",
		Size:      4096,
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected configured large sqlite to be inspected, got %#v", evaluation)
	}
}

func TestEngineEvaluatesZIPArchiveWithWindowsCredentialStorePaths(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234":       []byte("synthetic credstore marker"),
		"Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21/masterkey": []byte("synthetic protect marker"),
		"docs/readme.txt": []byte("synthetic notes"),
	})
	meta := FileMetadata{
		FilePath:  "Archive/profile-backup.zip",
		Name:      "profile-backup.zip",
		Extension: ".zip",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected archive findings, got %#v", evaluation)
	}

	foundCreds := false
	foundProtect := false
	for _, finding := range evaluation.Findings {
		switch finding.FilePath {
		case "Archive/profile-backup.zip!Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234":
			foundCreds = true
		case "Archive/profile-backup.zip!Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21/masterkey":
			foundProtect = true
		}
	}
	if !foundCreds || !foundProtect {
		t.Fatalf("expected archive member path findings for credential-store paths, got %#v", evaluation.Findings)
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

func TestEngineMatchesNorwegianCredentialLabels(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Users/Alice/Desktop/cred-notes.txt",
		Name:      "cred-notes.txt",
		Extension: ".txt",
		Size:      256,
	}
	content := []byte("Domene administrator: svc_backup\nPassord: FAKE_DB_PASSWORD_001\nDomene: essos.local\n")

	evaluation := engine.Evaluate(meta, content)

	foundPassword := false
	foundNoteStyle := false
	for _, finding := range evaluation.Findings {
		for _, ruleID := range finding.MatchedRuleIDs {
			switch ruleID {
			case "content.password_assignment_indicators":
				foundPassword = true
			case "content.note_style_credential_pair_indicators":
				foundNoteStyle = true
			}
		}
		switch finding.RuleID {
		case "content.password_assignment_indicators":
			foundPassword = true
		case "content.note_style_credential_pair_indicators":
			foundNoteStyle = true
		}
	}
	if !foundPassword {
		t.Fatalf("expected Passord label to trigger password assignment indicators, got %#v", evaluation.Findings)
	}
	if !foundNoteStyle {
		t.Fatalf("expected Domene administrator label to trigger note-style credential pair indicators, got %#v", evaluation.Findings)
	}
}

func TestEngineDetectsExecutableConfigXMLCredentials(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "install/VOBarnehageApplicationService.exe.config",
		Name:      "VOBarnehageApplicationService.exe.config",
		Extension: ".config",
		Size:      512,
	}
	content := []byte(`
<configuration>
  <appSettings>
    <add key="OleDbConnection" value="Provider=SQLOLEDB.1;data source=ha-db-01;initial catalog=U_RESSURSSTYRING;user id=VER;password=Winter2025!" />
    <add key="DatabasePassword" value="JvLGRifzatx+57lSEubUTkfH68fRD9eI/87s+/5Of4M=" />
  </appSettings>
</configuration>`)

	evaluation := engine.Evaluate(meta, content)

	foundConnectionString := false
	foundSecretAssignment := false
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "dbinspect.access.connection_string" {
			foundConnectionString = true
		}
		if finding.RuleID == "content.secret_assignment_indicators" || containsString(finding.MatchedRuleIDs, "content.secret_assignment_indicators") {
			foundSecretAssignment = true
		}
	}
	if !foundConnectionString {
		t.Fatalf("expected validated connection-string finding from .exe.config XML attributes, got %#v", evaluation.Findings)
	}
	if !foundSecretAssignment {
		t.Fatalf("expected XML appSettings secret/password finding from .exe.config, got %#v", evaluation.Findings)
	}
}

func TestEngineDoesNotTreatURISchemesAsCredentialPairs(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:       "10.0.1.40",
		Share:      "SYSVOL",
		FilePath:   "ha.no/scripts/Backup/2017-April/kix2010.txt",
		Name:       "kix2010.txt",
		Extension:  ".txt",
		Size:       512,
		FromSYSVOL: true,
		Priority:   92,
	}
	content := []byte("http://www.kixtart.org\nhttps://internal.example.local\nftp://server/path\n")

	evaluation := engine.Evaluate(meta, content)
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "content.note_style_credential_pair_indicators" {
			t.Fatalf("expected URI schemes to avoid note-style credential matches, got %#v", evaluation.Findings)
		}
		if strings.EqualFold(strings.TrimSpace(finding.PotentialAccount), "http") ||
			strings.EqualFold(strings.TrimSpace(finding.PotentialAccount), "https") ||
			strings.EqualFold(strings.TrimSpace(finding.PotentialAccount), "ftp") {
			t.Fatalf("expected URI schemes to avoid potential-account extraction, got %#v", evaluation.Findings)
		}
	}
}

func TestEngineDoesNotTreatGenericResourceAssignmentsAsCredentialPairs(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Install/langpack.ini",
		Name:      "langpack.ini",
		Extension: ".ini",
		Size:      256,
	}
	content := []byte("msg1=Installasjon\nmsg2=Avinstallering\nmsg3=Oppgradering\n")

	evaluation := engine.Evaluate(meta, content)
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "content.note_style_credential_pair_indicators" || finding.RuleID == "content.password_assignment_indicators" {
			t.Fatalf("expected generic resource assignments to avoid credential findings, got %#v", evaluation.Findings)
		}
	}
}

func TestEngineKeepsValidNoteStyleCredentialPairs(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	meta := FileMetadata{
		Host:       "10.0.1.40",
		Share:      "SYSVOL",
		FilePath:   "ha.no/scripts/Backup/2025-October/cred-notes.txt",
		Name:       "cred-notes.txt",
		Extension:  ".txt",
		Size:       512,
		FromSYSVOL: true,
		Priority:   92,
	}
	content := []byte("username: admin\npassword: Winter2025!\nuser=svc_sql\n")

	evaluation := engine.Evaluate(meta, content)

	var noteStyle *Finding
	for i := range evaluation.Findings {
		finding := &evaluation.Findings[i]
		if containsString(finding.MatchedRuleIDs, "content.note_style_credential_pair_indicators") {
			noteStyle = finding
		}
	}
	if noteStyle == nil {
		t.Fatalf("expected valid note-style credential pair finding, got %#v", evaluation.Findings)
	}
	if strings.EqualFold(strings.TrimSpace(noteStyle.PotentialAccount), "http") ||
		strings.EqualFold(strings.TrimSpace(noteStyle.PotentialAccount), "https") ||
		strings.EqualFold(strings.TrimSpace(noteStyle.PotentialAccount), "ftp") {
		t.Fatalf("expected note-style potential account to avoid URI schemes, got %#v", noteStyle)
	}
	if noteStyle.MatchedText == "" {
		t.Fatalf("expected note-style finding to retain matched content, got %#v", noteStyle)
	}
	if !containsString(noteStyle.MatchedRuleIDs, "content.password_assignment_indicators") {
		t.Fatalf("expected correlated finding to retain password assignment evidence, got %#v", noteStyle)
	}
	if noteStyle.ConfidenceScore < 70 || noteStyle.Confidence != "high" {
		t.Fatalf("expected valid content evidence in SYSVOL to still promote strongly, got %#v", noteStyle)
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
	memberPaths := make(map[string]struct{})
	for _, finding := range evaluation.Findings {
		memberPaths[finding.ArchiveMemberPath] = struct{}{}
	}
	if len(memberPaths) != 1 {
		t.Fatalf("expected only one archive member to be inspected after limits, got %#v", evaluation.Findings)
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

func TestEngineEvaluatesZIPArchiveWithPrivateKeyAndClientAuthMembers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"keys/id_rsa":     []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nLAB_ONLY_SYNTHETIC\n-----END OPENSSH PRIVATE KEY-----\n"),
		"vpn/client.ovpn": []byte("client\nauth-user-pass creds.txt\nremote vpn.lab.example.invalid 1194\n"),
		"ssh/known_hosts": []byte("vpn.lab.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly\n"),
		"docs/readme.txt": []byte("synthetic notes"),
	})
	meta := FileMetadata{
		FilePath:  "Archive/ssh-recovery.zip",
		Name:      "ssh-recovery.zip",
		Extension: ".zip",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from archive-contained private key artifacts, got %#v", evaluation)
	}

	foundPrivateKey := false
	foundOVPN := false
	for _, finding := range evaluation.Findings {
		switch finding.FilePath {
		case "Archive/ssh-recovery.zip!keys/id_rsa":
			foundPrivateKey = true
		case "Archive/ssh-recovery.zip!vpn/client.ovpn":
			foundOVPN = true
		}
	}
	if !foundPrivateKey || !foundOVPN {
		t.Fatalf("expected archive member findings for private key and ovpn, got %#v", evaluation.Findings)
	}
}

func TestEngineEvaluatesTARArchiveMembers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	content := buildTARFixture(t, ".tar.gz", map[string][]byte{
		"app/.env":         []byte("DB_PASSWORD=Winter2025!\n"),
		"configs/app.ini":  []byte("username=svc_backup\npassword=Winter2025!\n"),
		"nested/inner.tar": buildTARFixture(t, ".tar", map[string][]byte{"secret.txt": []byte("password=Winter2025!\n")}),
	})
	meta := FileMetadata{
		FilePath:  "Archive/deploy-configs.tar.gz",
		Name:      "deploy-configs.tar.gz",
		Extension: ".gz",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from tar.gz content, got %#v", evaluation)
	}
	for _, finding := range evaluation.Findings {
		if finding.ArchivePath != "Archive/deploy-configs.tar.gz" {
			t.Fatalf("expected tar archive metadata on finding, got %#v", finding)
		}
		if strings.Contains(finding.FilePath, "inner.tar") {
			t.Fatalf("expected nested tar member to be skipped, got %#v", evaluation.Findings)
		}
	}
}

func TestEngineSkipsOversizedTARArchivesByDefault(t *testing.T) {
	t.Parallel()

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := FileMetadata{
		FilePath:  "Archive/large.tgz",
		Name:      "large.tgz",
		Extension: ".tgz",
		Size:      10*1024*1024 + 1,
	}

	if engine.NeedsContent(meta) {
		t.Fatal("expected oversized tgz to skip content reads by default")
	}
	evaluation := engine.Evaluate(meta, nil)
	if !evaluation.Skipped || !strings.Contains(evaluation.SkipReason, "automatic inspection limit") {
		t.Fatalf("expected automatic tar size skip, got %#v", evaluation)
	}
}

func TestEngineEvaluatesDOCXMembers(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"[Content_Types].xml":   []byte(`<Types></Types>`),
		"_rels/.rels":           []byte(`<Relationships></Relationships>`),
		"word/document.xml":     []byte(`<w:document><w:body><w:p><w:r><w:t>service_account=svc_backup</w:t></w:r></w:p><w:p><w:r><w:t>password=FAKE_DB_PASSWORD_001</w:t></w:r></w:p><w:p><w:r><w:t>client_secret=SAMPLE_CLIENT_SECRET_001</w:t></w:r></w:p><w:p><w:r><w:t>Server=db01.example.local;Database=Payroll;User Id=svc_payroll_db;Password=FAKE_DB_PASSWORD_001;</w:t></w:r></w:p></w:body></w:document>`),
		"word/media/image1.png": append([]byte{0x89, 'P', 'N', 'G', 0x00}, bytes.Repeat([]byte{0x01}, 32)...),
	})
	meta := FileMetadata{
		FilePath:  "Docs/credentials.docx",
		Name:      "credentials.docx",
		Extension: ".docx",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from docx content, got %#v", evaluation)
	}
	foundContent := false
	for _, finding := range evaluation.Findings {
		if finding.ArchivePath != "Docs/credentials.docx" || finding.ArchiveMemberPath != "word/document.xml" {
			t.Fatalf("expected Office archive metadata on finding, got %#v", finding)
		}
		if finding.RuleID == "content.password_assignment_indicators" || finding.RuleID == "content.secret_assignment_indicators" || finding.RuleID == "content.database_connection_string_indicators" || finding.RuleID == "dbinspect.access.connection_string" {
			foundContent = true
		}
	}
	if !foundContent {
		t.Fatalf("expected content-driven docx findings, got %#v", evaluation.Findings)
	}
}

func TestEngineEvaluatesXLSXSharedStrings(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"[Content_Types].xml":      []byte(`<Types></Types>`),
		"_rels/.rels":              []byte(`<Relationships></Relationships>`),
		"xl/sharedStrings.xml":     []byte(`<sst><si><t>db_user=svc_payroll_db</t></si><si><t>db_password=FAKE_DB_PASSWORD_001</t></si><si><t>client_secret=SAMPLE_CLIENT_SECRET_001</t></si><si><t>postgresql://svc_payroll_db:FAKE_DB_PASSWORD_001@db-finance.example.invalid/snablr_finance?sslmode=require</t></si></sst>`),
		"xl/worksheets/sheet1.xml": []byte(`<worksheet><sheetData><row><c t="s"><v>0</v></c></row></sheetData></worksheet>`),
	})
	meta := FileMetadata{
		FilePath:  "Finance/db-access.xlsx",
		Name:      "db-access.xlsx",
		Extension: ".xlsx",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from xlsx content, got %#v", evaluation)
	}
	foundSharedStrings := false
	foundContent := false
	for _, finding := range evaluation.Findings {
		if finding.ArchiveMemberPath == "xl/sharedStrings.xml" {
			foundSharedStrings = true
		}
		if finding.RuleID == "content.password_assignment_indicators" || finding.RuleID == "content.secret_assignment_indicators" || finding.RuleID == "dbinspect.access.connection_string" {
			foundContent = true
		}
	}
	if !foundSharedStrings {
		t.Fatalf("expected xlsx findings to point at sharedStrings, got %#v", evaluation.Findings)
	}
	if !foundContent {
		t.Fatalf("expected content-driven xlsx findings, got %#v", evaluation.Findings)
	}
}

func TestEngineEvaluatesPPTXSlideText(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	content := buildZIPFixture(t, map[string][]byte{
		"[Content_Types].xml":   []byte(`<Types></Types>`),
		"_rels/.rels":           []byte(`<Relationships></Relationships>`),
		"ppt/slides/slide1.xml": []byte(`<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>remote=vpn-prod.example.invalid</a:t></a:r></a:p><a:p><a:r><a:t>shared_secret=SAMPLE_CLIENT_SECRET_001</a:t></a:r></a:p><a:p><a:r><a:t>password=FAKE_DB_PASSWORD_001</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`),
	})
	meta := FileMetadata{
		FilePath:  "Presentations/vpn-rollout.pptx",
		Name:      "vpn-rollout.pptx",
		Extension: ".pptx",
		Size:      int64(len(content)),
	}

	evaluation := engine.Evaluate(meta, content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from pptx content, got %#v", evaluation)
	}
	foundContent := false
	for _, finding := range evaluation.Findings {
		if finding.ArchiveMemberPath != "ppt/slides/slide1.xml" {
			t.Fatalf("expected pptx findings to stay on slide xml members, got %#v", evaluation.Findings)
		}
		if finding.RuleID == "content.password_assignment_indicators" || finding.RuleID == "content.secret_assignment_indicators" {
			foundContent = true
		}
	}
	if !foundContent {
		t.Fatalf("expected content-driven pptx findings, got %#v", evaluation.Findings)
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

func buildTARFixture(t *testing.T, ext string, members map[string][]byte) []byte {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range members {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%s) returned error: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("Write(%s) returned error: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if ext == ".tar" {
		return tarBuf.Bytes()
	}

	var gzipBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzipBuf, gzip.NoCompression)
	if err != nil {
		t.Fatalf("NewWriterLevel returned error: %v", err)
	}
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write returned error: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close returned error: %v", err)
	}
	return gzipBuf.Bytes()
}

func buildSQLiteDBFixture(t *testing.T, statements []string) []byte {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "snablr-scanner-sqlite-*.db")
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

func archiveOptionsForTests(mutate func(*archiveinspect.Options)) archiveinspect.Options {
	opts := archiveinspect.Options{
		Enabled:                  true,
		AutoZIPMaxSize:           10 * 1024 * 1024,
		AllowLargeZIPs:           false,
		MaxZIPSize:               10 * 1024 * 1024,
		AutoTARMaxSize:           10 * 1024 * 1024,
		AllowLargeTARs:           false,
		MaxTARSize:               10 * 1024 * 1024,
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

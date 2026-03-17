package scanner

import (
	"path/filepath"
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
			Match:               "password=EXAMPLE_PASSWORD_001",
			MatchedText:         "password=EXAMPLE_PASSWORD_001",
			MatchedTextRedacted: "password=********",
			Snippet:             "password=********",
			Context:             "password=EXAMPLE_PASSWORD_001",
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

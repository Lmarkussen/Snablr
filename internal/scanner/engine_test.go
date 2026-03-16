package scanner

import (
	"path/filepath"
	"testing"

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

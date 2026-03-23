package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/diff"
	"snablr/internal/scanner"
	"snablr/internal/seed"
)

func sampleFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:          "content.synthetic_password",
		RuleName:        "Synthetic Password",
		Severity:        "high",
		Confidence:      "high",
		RuleConfidence:  "medium",
		ConfidenceScore: 78,
		ConfidenceReasons: []string{
			"content rule matched \"password = ReplaceMe123!\" for Detect a synthetic password assignment.",
			"path contains high-value keywords associated with sensitive or operational content",
			"multiple independent signal types increased confidence",
		},
		Category:    "credentials",
		TriageClass: "actionable",
		Actionable:  true,
		Correlated:  true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   78,
			FinalScore:                  78,
			ContentSignalStrength:       32,
			HeuristicSignalContribution: 18,
			ValueQualityScore:           14,
			ValueQualityLabel:           "high",
			ValueQualityReason:          "content includes non-placeholder secret-like or credential-like values",
			CorrelationContribution:     14,
			PathContextContribution:     14,
		},
		Priority:            95,
		PriorityReason:      "test priority reason",
		SharePriority:       90,
		SharePriorityReason: "high-value share",
		FilePath:            "Policies/Groups.xml",
		Share:               "SYSVOL",
		ShareDescription:    "Domain policies and scripts",
		ShareType:           "sysvol",
		Host:                "dc01",
		Source:              "dfs",
		DFSNamespacePath:    `\\example.local\dfs\policies`,
		DFSLinkPath:         "Policies/Groups.xml",
		SignalType:          "content",
		Match:               "password = ReplaceMe123!",
		MatchedText:         "password = ReplaceMe123!",
		MatchedTextRedacted: "password = ********",
		Snippet:             "user = alice\npassword = ReplaceMe123!\ndomain = example.local",
		Context:             "user = alice\npassword = ReplaceMe123!\ndomain = example.local",
		ContextRedacted:     "user = alice\npassword = ********\ndomain = example.local",
		PotentialAccount:    "user = alice",
		LineNumber:          12,
		MatchReason:         "file contents contained text that matches the rule.",
		RuleExplanation:     "This synthetic pattern simulates a hardcoded password assignment in a config-like file.",
		RuleRemediation:     "Move credentials into a managed secret store or environment-specific secret injection path.",
		FromSYSVOL:          true,
		MatchedRuleIDs:      []string{"content.synthetic_password", "filename.synthetic_env"},
		MatchedSignalTypes:  []string{"content", "filename", "path", "share_priority", "planner_priority"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "content", RuleID: "content.synthetic_password", RuleName: "Synthetic Password", Match: "password = ReplaceMe123!", Confidence: "medium", Weight: 32, Reason: "content rule matched \"password = ReplaceMe123!\" for Detect a synthetic password assignment."},
			{SignalType: "filename", RuleID: "filename.synthetic_env", RuleName: "Synthetic Env File", Match: "Groups.xml", Weight: 18, Reason: "filename rule matched \"Groups.xml\" for Detect a synthetic env file name."},
			{SignalType: "path", Weight: 12, Reason: "path suggests policy, preference, or script review material"},
			{SignalType: "share_priority", Weight: 12, Reason: "SYSVOL is treated as a high-value AD share"},
			{SignalType: "planner_priority", Weight: 12, Reason: "planner marked this file path as high-priority review material"},
		},
		Tags: []string{"credentials", "source:dfs", "ad-share:sysvol"},
	}
}

func sampleHeuristicFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "filename.password_export",
		RuleName:          "Password Export Filename",
		Severity:          "medium",
		Confidence:        "medium",
		RuleConfidence:    "medium",
		ConfidenceScore:   38,
		ConfidenceReasons: []string{"filename rule matched \"passwords\" for Detect credential-style exports.", "planner marked this path as relevant review material"},
		Category:          "credentials",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   38,
			FinalScore:                  38,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 18,
			ValueQualityScore:           0,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from metadata and context rather than extracted value quality",
			CorrelationContribution:     8,
			PathContextContribution:     12,
		},
		Priority:            72,
		PriorityReason:      "test filename priority reason",
		SharePriority:       60,
		SharePriorityReason: "user profile share",
		FilePath:            "Users/Alice/Desktop/passwords.txt",
		Share:               "Users",
		ShareDescription:    "User profile home directories",
		ShareType:           "disk",
		Host:                "fs01",
		Source:              "cli",
		SignalType:          "filename",
		Match:               "passwords",
		MatchedText:         "passwords",
		MatchedTextRedacted: "passwords",
		MatchReason:         "filename matched a heuristic naming pattern covered by the rule.",
		RuleExplanation:     "This heuristic catches filenames that commonly indicate plaintext credential exports.",
		RuleRemediation:     "Review the file contents and remove plaintext secrets from shared locations.",
		MatchedRuleIDs:      []string{"filename.password_export"},
		MatchedSignalTypes:  []string{"filename", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.password_export", RuleName: "Password Export Filename", Match: "passwords", Confidence: "medium", Weight: 18, Reason: "filename rule matched \"passwords\" for Detect credential-style exports."},
			{SignalType: "path", Weight: 12, Reason: "path contains a desktop-style review location"},
		},
		Tags: []string{"credentials", "filenames", "review"},
	}
}

func sampleNTDSFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.secret_store_artifacts",
		RuleName:           "Secret Store Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Archive/Recovery/AD/NTDS.DIT",
		Share:              "Archive",
		Host:               "dc01",
		SignalType:         "filename",
		Match:              "NTDS.DIT",
		MatchedText:        "NTDS.DIT",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.secret_store_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.secret_store_artifacts", RuleName: "Secret Store Artifacts", Match: "NTDS.DIT", Confidence: "high", Weight: 18, Reason: "exact AD database artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store"},
	}
}

func sampleSystemHiveFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.windows_hive_artifacts",
		RuleName:           "Windows Hive Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Archive/Recovery/AD/SYSTEM",
		Share:              "Archive",
		Host:               "dc01",
		SignalType:         "filename",
		Match:              "SYSTEM",
		MatchedText:        "SYSTEM",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.windows_hive_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.windows_hive_artifacts", RuleName: "Windows Hive Artifacts", Match: "SYSTEM", Confidence: "high", Weight: 18, Reason: "exact SYSTEM hive artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store", "windows"},
	}
}

func sampleConfigOnlyFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "filename.sensitive_config_names",
		RuleName:          "Sensitive Config Names",
		Severity:          "low",
		Confidence:        "low",
		RuleConfidence:    "high",
		ConfidenceScore:   24,
		ConfidenceReasons: []string{"configuration artifact was identified without actionable evidence"},
		Category:          "configuration",
		TriageClass:       "config-only",
		Actionable:        false,
		Correlated:        false,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   24,
			FinalScore:                  24,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 24,
			ValueQualityScore:           0,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from metadata and context rather than extracted value quality",
			CorrelationContribution:     0,
			PathContextContribution:     0,
		},
		Priority:            48,
		PriorityReason:      "config path",
		FilePath:            "Apps/appsettings.json",
		Share:               "Apps",
		ShareType:           "disk",
		Host:                "fs01",
		Source:              "file",
		SignalType:          "filename",
		Match:               "appsettings.json",
		MatchedText:         "appsettings.json",
		MatchedTextRedacted: "appsettings.json",
		MatchReason:         "filename matched a heuristic naming pattern covered by the rule.",
		RuleExplanation:     "Common configuration names often deserve review, but this alone is not actionable.",
		RuleRemediation:     "Review the file only if paired with stronger evidence such as embedded credentials or validated connection details.",
		MatchedRuleIDs:      []string{"filename.sensitive_config_names"},
		MatchedSignalTypes:  []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.sensitive_config_names", RuleName: "Sensitive Config Names", Match: "appsettings.json", Confidence: "high", Weight: 18, Reason: "filename rule matched \"appsettings.json\" for Detect common config filenames that frequently contain environment settings or embedded secrets."},
		},
		Tags: []string{"configuration", "filenames", "triage"},
	}
}

func sampleArchiveFinding() scanner.Finding {
	finding := sampleFinding()
	finding.FilePath = "Deploy/loot.zip!configs/web.config"
	finding.ArchivePath = "Deploy/loot.zip"
	finding.ArchiveMemberPath = "configs/web.config"
	finding.ArchiveLocalInspect = true
	return finding
}

func writeValidationManifest(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "seed-manifest.json")
	manifest := seed.Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []seed.SeedManifestEntry{
			{
				Host:          "dc01",
				Share:         "SYSVOL",
				Path:          "Policies/Groups.xml",
				Category:      "database",
				ExpectedClass: "actionable",
			},
			{
				Host:          "fs01",
				Share:         "Apps",
				Path:          "Apps/appsettings.json",
				Category:      "database",
				ExpectedClass: "config-only",
			},
			{
				Host:          "fs01",
				Share:         "Deploy",
				Path:          "Deploy/app.env",
				Category:      "database",
				ExpectedClass: "weak-review",
			},
			{
				Host:          "fs01",
				Share:         "Deploy",
				Path:          "Deploy/appsettings.json",
				Category:      "database",
				ExpectedClass: "correlated-high-confidence",
			},
		},
	}
	if err := manifest.Write(path); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	return path
}

func TestJSONWriterGeneratesStructuredReport(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].DFSNamespacePath == "" || !report.Findings[0].FromSYSVOL {
		t.Fatalf("expected DFS and SYSVOL metadata, got %#v", report.Findings[0])
	}
	if report.Findings[0].ShareType != "sysvol" || report.Findings[0].ShareDescription != "Domain policies and scripts" {
		t.Fatalf("expected share metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].Confidence != "high" || report.Findings[0].RuleConfidence != "medium" || report.Findings[0].RuleExplanation == "" || report.Findings[0].RuleRemediation == "" {
		t.Fatalf("expected explainability metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].SignalType != "content" || report.Findings[0].MatchedTextRedacted == "" || report.Findings[0].LineNumber != 12 || report.Findings[0].ContextRedacted == "" || report.Findings[0].PotentialAccount != "user = alice" {
		t.Fatalf("expected signal-specific content metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].ConfidenceScore == 0 || len(report.Findings[0].MatchedRuleIDs) != 2 || len(report.Findings[0].SupportingSignals) == 0 {
		t.Fatalf("expected correlated signal metadata in JSON finding, got %#v", report.Findings[0])
	}
	if !report.Findings[0].Actionable || !report.Findings[0].Correlated || report.Findings[0].TriageClass != "actionable" {
		t.Fatalf("expected triage metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].ConfidenceBreakdown.BaseScore != 78 || report.Findings[0].ConfidenceBreakdown.ValueQualityScore == 0 || report.Findings[0].ConfidenceBreakdown.CorrelationContribution == 0 {
		t.Fatalf("expected confidence breakdown in JSON finding, got %#v", report.Findings[0].ConfidenceBreakdown)
	}
	if len(report.CategorySummaries) != 1 || report.CategorySummaries[0].Category != "credentials" {
		t.Fatalf("unexpected category summaries: %#v", report.CategorySummaries)
	}
	if report.Performance == nil || report.Performance.FilesScanned != 1 || report.Performance.FindingsTotal != 1 || report.Performance.DurationMS < 0 {
		t.Fatalf("expected performance summary in JSON report, got %#v", report.Performance)
	}
	if len(report.Performance.ClassificationDistribution) == 0 || report.Performance.ClassificationDistribution[0].Class != "actionable" {
		t.Fatalf("expected classification distribution in performance summary, got %#v", report.Performance)
	}
}

func TestAugmentFindingsForReportingAddsADCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleNTDSFinding(),
		sampleSystemHiveFinding(),
	})

	if len(augmented) != 3 {
		t.Fatalf("expected raw findings plus one correlated AD finding, got %#v", augmented)
	}

	found := false
	for _, finding := range augmented {
		if finding.RuleID != adCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "active-directory" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated AD finding: %#v", finding)
		}
		if finding.FilePath != sampleNTDSFinding().FilePath || finding.Confidence != "high" {
			t.Fatalf("expected NTDS anchor and high confidence, got %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated AD finding in augmented results, got %#v", augmented)
	}
}

func TestJSONWriterIncludesADCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(sampleNTDSFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSystemHiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if report.Summary.MatchesFound != 3 || len(report.Findings) != 3 {
		t.Fatalf("expected augmented findings in summary and JSON output, got summary=%#v findings=%#v", report.Summary, report.Findings)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.RuleID != adCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "active-directory" || !finding.Correlated || finding.SignalType != "correlation" {
			t.Fatalf("unexpected correlated JSON finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated AD finding in JSON report, got %#v", report.Findings)
	}
}

func TestJSONWriterIncludesDiffSummaryWhenBaselineIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetBaselineFindings([]scanner.Finding{
		{
			RuleID:         "content.synthetic_password",
			RuleName:       "Synthetic Password",
			Severity:       "medium",
			Category:       "credentials",
			FilePath:       "Policies/Groups.xml",
			Share:          "SYSVOL",
			Host:           "dc01",
			Match:          "password = ReplaceMe123!",
			MatchedRuleIDs: []string{"content.synthetic_password", "filename.synthetic_env"},
		},
		{
			RuleID:   "content.old_only",
			RuleName: "Old Only",
			Severity: "low",
			Category: "credentials",
			FilePath: "Policies/Old.xml",
			Share:    "SYSVOL",
			Host:     "dc01",
			Match:    "old",
		},
	})
	writer.SetBaselinePerformance(&diff.PerformanceSummary{
		FilesScanned:   10,
		FindingsTotal:  2,
		DurationMS:     500,
		FilesPerSecond: 20,
		ClassificationDistribution: []diff.ClassificationSummary{
			{Class: "actionable", Count: 2},
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.DiffSummary == nil {
		t.Fatalf("expected diff summary in report")
	}
	if report.DiffSummary.Changed != 1 || report.DiffSummary.Removed != 1 {
		t.Fatalf("unexpected diff summary: %#v", report.DiffSummary)
	}
	if report.Findings[0].DiffStatus != string(diff.StatusChanged) {
		t.Fatalf("expected changed diff status, got %#v", report.Findings[0])
	}
	if len(report.Findings[0].ChangedFields) == 0 {
		t.Fatalf("expected changed fields metadata, got %#v", report.Findings[0])
	}
	if report.PerformanceComparison == nil || report.PerformanceComparison.FindingsDelta != -1 {
		t.Fatalf("expected performance comparison in report, got %#v", report.PerformanceComparison)
	}
}

func TestJSONWriterIncludesValidationSummaryWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Validation == nil || !report.Validation.HasValidation {
		t.Fatalf("expected validation summary, got %#v", report.Validation)
	}
	if report.Validation.ExpectedItems != 4 || report.Validation.FoundItems != 2 || report.Validation.MissedItems != 2 {
		t.Fatalf("unexpected validation summary: %#v", report.Validation)
	}
	if len(report.Validation.ClassCoverage) == 0 || len(report.Validation.MissedExpected) != 2 {
		t.Fatalf("expected class coverage and missed expected items, got %#v", report.Validation)
	}
}

func TestJSONWriterIncludesValidationModeSummaryWhenEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetValidationMode(true)
	writer.RecordSkip(scanner.FileMetadata{FilePath: "skip.txt"}, "max size")
	writer.RecordSuppressedFinding(scanner.SuppressedFinding{FilePath: "suppressed.env", RuleID: "content.password_assignment_indicators"})
	writer.RecordVisibleFinding(sampleFinding())
	writer.RecordVisibleFinding(sampleConfigOnlyFinding())
	writer.RecordDowngradedFinding(sampleConfigOnlyFinding())
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.ValidationMode == nil || !report.ValidationMode.Enabled {
		t.Fatalf("expected validation mode summary, got %#v", report.ValidationMode)
	}
	if report.ValidationMode.SuppressedFindings != 1 || report.ValidationMode.VisibleFindings != 2 || report.ValidationMode.DowngradedFindings != 1 {
		t.Fatalf("unexpected validation mode counts: %#v", report.ValidationMode)
	}
}

func TestJSONWriterIncludesArchiveMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(sampleArchiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", report.Findings)
	}
	finding := report.Findings[0]
	if finding.ArchivePath != "Deploy/loot.zip" || finding.ArchiveMemberPath != "configs/web.config" || !finding.ArchiveLocalInspect {
		t.Fatalf("expected archive metadata in JSON output, got %#v", finding)
	}
}

func TestConsoleWriterIncludesContextMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Share Type: sysvol", "Share Description: Domain policies and scripts", "Source: dfs", "AD Share: SYSVOL", "DFS Namespace:", "Confidence: HIGH (78)", "Matched Rules:", "Signals:", "Signal: content", "Line: 12", "Potential account context: user = alice", "Matched text: password = ReplaceMe123!", "Context:", "domain = example.local", "Confidence Raised By:", "Rule Note:", "Remediation:", "Performance: files_scanned=0 findings=1", "Classification Distribution: actionable=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesPerformanceComparisonWhenBaselineIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetBaselinePerformance(&diff.PerformanceSummary{
		FilesScanned:   5,
		FindingsTotal:  2,
		DurationMS:     250,
		FilesPerSecond: 20,
		ClassificationDistribution: []diff.ClassificationSummary{
			{Class: "actionable", Count: 2},
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Performance Comparison:", "Classification Changes:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesValidationSummaryWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Validation: expected=4 found=2 missed=2", "Validation Classes:", "informational:", "actionable:", "Validation Missed:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesValidationModeSummaryWhenEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetValidationMode(true)
	writer.RecordSkip(scanner.FileMetadata{FilePath: "skip.txt"}, "max size")
	writer.RecordSuppressedFinding(scanner.SuppressedFinding{FilePath: "suppressed.env", RuleID: "content.password_assignment_indicators"})
	writer.RecordVisibleFinding(sampleFinding())
	writer.RecordVisibleFinding(sampleConfigOnlyFinding())
	writer.RecordDowngradedFinding(sampleConfigOnlyFinding())
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Validation Mode: total=3 suppressed=1 visible=2 downgraded=1", "high_confidence=1", "skipped_files=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestHTMLWriterRendersStandaloneTriageReport(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleHeuristicFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Snablr Scan Report", "Version", "quickFilter", "severityFilter", "categoryFilter", "confidenceFilter", "sourceFilter", "signalFilter", "scopeFilter", "correlatedOnly", "hideConfigOnly", "hideLowConfidence", "hideNonActionable", "resetFilters", "filterStatus", "Severity Summary", "Category Summary", "Host Summary", "SYSVOL", "Signal Type", "Password Export Filename", "Show Evidence", "Visible Evidence", "Raw Supporting Signals", "password = ReplaceMe123!", "user = alice", "Line Number", "Heuristic file hit", "Config artifact only.", "filename matched a heuristic naming pattern covered by the rule.", "Rule Explanation", "confidence high", "Supporting Signals", "Confidence Breakdown", "Content signal strength", "Value quality:", "Final score:", "Remediation", "data-triage=\"config-only\"", "data-actionable=\"false\""} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterShowsDiffSummaryAndHighlights(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.SetBaselineFindings([]scanner.Finding{
		{
			RuleID:         sampleFinding().RuleID,
			RuleName:       sampleFinding().RuleName,
			Severity:       "medium",
			Category:       sampleFinding().Category,
			FilePath:       sampleFinding().FilePath,
			Share:          sampleFinding().Share,
			Host:           sampleFinding().Host,
			Match:          sampleFinding().Match,
			MatchedRuleIDs: append([]string{}, sampleFinding().MatchedRuleIDs...),
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Baseline Diff", "Changed Since Baseline", "badge diff-changed", "status-changed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterIncludesValidationSectionWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Seeded Validation", "Config Suppressed", "Actionable Promoted", "Over-Promoted Items", "Missed Expected Items", "correlated / high-confidence"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersADCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleNTDSFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSystemHiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"correlation.ad.ntds_system", "signal correlation", "NTDS.DIT and SYSTEM artifacts were found together in the same directory context"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersArchiveMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleArchiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Deploy/loot.zip!configs/web.config", "Archive Member", "configs/web.config", "Archive Inspection", "local"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestCSVWriterEmitsHeaderAndFindingRow(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewCSVWriter(&buf, nil)
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected header and one row, got %d rows", len(rows))
	}
	if rows[0][0] != "host" || rows[1][0] != "dc01" {
		t.Fatalf("unexpected csv contents: %#v", rows)
	}
}

func TestMarkdownWriterGeneratesSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewMarkdownWriter(&buf, nil)
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"# Snablr Scan Summary", "## Summary", "## Categories", "## Findings", "Synthetic Password", "Domain policies and scripts"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected markdown output to contain %q", want)
		}
	}
}

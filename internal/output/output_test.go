package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"snablr/internal/diff"
	"snablr/internal/scanner"
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
		Category:            "credentials",
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
		Match:               "password = ReplaceMe123!",
		Snippet:             `password = ReplaceMe123!`,
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
	if report.Findings[0].ConfidenceScore == 0 || len(report.Findings[0].MatchedRuleIDs) != 2 || len(report.Findings[0].SupportingSignals) == 0 {
		t.Fatalf("expected correlated signal metadata in JSON finding, got %#v", report.Findings[0])
	}
	if len(report.CategorySummaries) != 1 || report.CategorySummaries[0].Category != "credentials" {
		t.Fatalf("unexpected category summaries: %#v", report.CategorySummaries)
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
	for _, want := range []string{"Share Type: sysvol", "Share Description: Domain policies and scripts", "Source: dfs", "AD Share: SYSVOL", "DFS Namespace:", "Confidence: HIGH (78)", "Matched Rules:", "Signals:", "Confidence Raised By:", "Rule Note:", "Remediation:"} {
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
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Snablr Scan Report", "Version", "quickFilter", "Severity Summary", "Category Summary", "Host Summary", "SYSVOL", "Type: sysvol", "Description: Domain policies and scripts", "source dfs", "Correlated rules", "Signals:", "Rule Explanation", "confidence high", "Supporting Signals", "Remediation"} {
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

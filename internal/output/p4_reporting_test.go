package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

func p4ReportFinding(observationID, match string) scanner.Finding {
	return scanner.Finding{
		RuleID: "dbinspect.infrastructure.structured_config", RuleName: "Configured endpoint",
		Category: "database-infrastructure", Severity: "medium", Confidence: "high",
		TriageClass: "confirmed", Host: "host", Share: "share", FilePath: "config.json",
		ObservationID: observationID, Match: match, MatchedText: `{"connections":{"production":{},"reporting":{}}}`,
		MatchedTextRedacted: `{"connections":{"production":{},"reporting":{}}}`, Context: match,
	}
}

func TestP4ReportDeduplicationPreservesDistinctDatabaseObservations(t *testing.T) {
	t.Parallel()

	findings := augmentFindingsForReporting([]scanner.Finding{
		p4ReportFinding("structured:0:production", "host=prod;database=prod"),
		p4ReportFinding("structured:1:reporting", "host=report;database=reporting"),
	})
	if len(findings) != 2 {
		t.Fatalf("report projection collapsed distinct P4 observations: %#v", findings)
	}
}

func TestP4JSONAndMarkdownRetainDistinctDatabaseObservations(t *testing.T) {
	t.Parallel()

	input := []scanner.Finding{
		p4ReportFinding("structured:0:production", "host=prod;database=prod"),
		p4ReportFinding("structured:1:reporting", "host=report;database=reporting"),
	}
	var jsonOut bytes.Buffer
	jsonWriter := NewJSONWriter(&jsonOut, nil, false)
	for _, finding := range input {
		if err := jsonWriter.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := jsonWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []struct {
			ObservationID string `json:"observation_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 || report.Findings[0].ObservationID == report.Findings[1].ObservationID {
		t.Fatalf("JSON did not retain distinct observations: %#v", report.Findings)
	}

	var markdownOut bytes.Buffer
	markdownWriter := NewMarkdownWriter(&markdownOut, nil)
	for _, finding := range input {
		if err := markdownWriter.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := markdownWriter.Close(); err != nil {
		t.Fatal(err)
	}
	markdown := markdownOut.String()
	if !strings.Contains(markdown, "host=prod;database=prod") || !strings.Contains(markdown, "host=report;database=reporting") {
		t.Fatalf("Markdown omitted distinct P4 evidence: %s", markdown)
	}
}

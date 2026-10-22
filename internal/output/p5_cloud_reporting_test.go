package output

import (
	"bytes"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

func p5CloudReportFinding(observationID, evidence string) scanner.Finding {
	return scanner.Finding{
		RuleID:              "cloudinspect.azure.client_secret_config",
		RuleName:            "Azure Client Secret Configuration",
		Category:            "application-cloud-secrets",
		Severity:            "high",
		Confidence:          "high",
		TriageClass:         "confirmed",
		Host:                "host",
		Share:               "share",
		FilePath:            "cloud.json",
		ObservationID:       observationID,
		MatchedText:         evidence,
		MatchedTextRedacted: evidence,
		Context:             evidence,
		Snippet:             evidence,
	}
}

func TestP5MarkdownRetainsDistinctCloudObservations(t *testing.T) {
	input := []scanner.Finding{
		p5CloudReportFinding("cloud-one", `{"principals":[{"client_secret":"one"}]}`),
		p5CloudReportFinding("cloud-two", `{"principals":[{"client_secret":"two"}]}`),
	}
	var output bytes.Buffer
	writer := NewMarkdownWriter(&output, nil)
	for _, finding := range input {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(output.String(), "Azure Client Secret Configuration"); got != 2 {
		t.Fatalf("Markdown collapsed distinct cloud observations: count=%d output=%s", got, output.String())
	}
}

func TestP5CloudReportDeduplicationRetainsOneDuplicateEmission(t *testing.T) {
	input := []scanner.Finding{
		p5CloudReportFinding("cloud-one", `{"client_secret":"one"}`),
		p5CloudReportFinding("cloud-one", `{"client_secret":"one"}`),
	}
	if got := len(augmentFindingsForReporting(input)); got != 1 {
		t.Fatalf("duplicate cloud emission was not deduplicated: %d", got)
	}
}

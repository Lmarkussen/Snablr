package output

import (
	"bytes"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

func TestWindowsArtifactEvidenceSurvivesReportWriters(t *testing.T) {
	evidence := "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Synthetic]\r\n\"Value\"=\"complete\"\r\n"
	finding := scanner.Finding{RuleID: "windowsinspect.registry_export.structured", RuleName: "Windows Registry Editor Export", Category: "windows-deployment", SignalType: "validated", Confidence: "high", TriageClass: "confirmed", FilePath: "export.reg", Match: "valid Registry Editor text export", MatchedText: evidence, Snippet: evidence, Context: evidence, ObservationID: "windowsinspect:test"}
	var jsonBuf bytes.Buffer
	jsonWriter := NewJSONWriter(&jsonBuf, nil, true)
	if err := jsonWriter.WriteFinding(finding); err != nil || jsonWriter.Close() != nil {
		t.Fatal("JSON writer failed")
	}
	if !strings.Contains(jsonBuf.String(), "Windows Registry Editor Version 5.00") || !strings.Contains(jsonBuf.String(), "complete") {
		t.Fatalf("JSON lost original evidence: %q", jsonBuf.String())
	}
	var csvBuf bytes.Buffer
	csvWriter := NewCSVWriter(&csvBuf, nil)
	if err := csvWriter.WriteFinding(finding); err != nil || csvWriter.Close() != nil {
		t.Fatal("CSV writer failed")
	}
	if !strings.Contains(csvBuf.String(), "Windows Registry Editor Version 5.00") || !strings.Contains(csvBuf.String(), "complete") {
		t.Fatalf("CSV lost original evidence: %q", csvBuf.String())
	}
	var mdBuf bytes.Buffer
	mdWriter := NewMarkdownWriter(&mdBuf, nil)
	if err := mdWriter.WriteFinding(finding); err != nil || mdWriter.Close() != nil {
		t.Fatal("Markdown writer failed")
	}
	if !strings.Contains(mdBuf.String(), "Windows Registry Editor Version 5.00") || !strings.Contains(mdBuf.String(), "complete") {
		t.Fatalf("Markdown lost original evidence: %q", mdBuf.String())
	}
	var htmlBuf bytes.Buffer
	htmlWriter, err := NewHTMLWriter(&htmlBuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := htmlWriter.WriteFinding(finding); err != nil || htmlWriter.Close() != nil {
		t.Fatal("HTML writer failed")
	}
	if !strings.Contains(htmlBuf.String(), "complete") || !strings.Contains(htmlBuf.String(), "Windows Registry Editor") {
		t.Fatalf("HTML lost original evidence: %q", htmlBuf.String())
	}
}

func TestP6ObservationIDsPreventReportCollapse(t *testing.T) {
	base := scanner.Finding{
		RuleID:        "sccminspect.task_sequence.step",
		RuleName:      "SCCM Task-Sequence Step",
		Category:      "windows-deployment",
		SignalType:    "content",
		FilePath:      "sequence.json",
		Match:         "same visible action",
		MatchedText:   "same visible action",
		Context:       "same visible action",
		ObservationID: "sccminspect:step-1",
	}
	second := base
	second.ObservationID = "sccminspect:step-2"
	if got := augmentFindingsForReporting([]scanner.Finding{base, second}); len(got) != 2 {
		t.Fatalf("distinct P6 observations collapsed: got %d findings: %#v", len(got), got)
	}
	duplicate := base
	if got := augmentFindingsForReporting([]scanner.Finding{base, duplicate}); len(got) != 1 {
		t.Fatalf("duplicate emission was not suppressed: got %d findings", len(got))
	}
}

func TestP6LongEvidenceRemainsCompleteAcrossReports(t *testing.T) {
	evidence := "BEGIN-P6-EVIDENCE\n" + strings.Repeat("SENTINEL-0123456789\n", 80) + "END-P6-EVIDENCE"
	finding := scanner.Finding{
		RuleID:      "windowsinspect.registry_export.structured",
		RuleName:    "Windows Registry Editor Export",
		Category:    "windows-deployment",
		FilePath:    "long.reg",
		Match:       "valid Registry Editor text export",
		MatchedText: evidence,
		Snippet:     evidence,
		Context:     evidence,
		Actionable:  true,
	}

	var jsonBuf bytes.Buffer
	jsonWriter := NewJSONWriter(&jsonBuf, nil, true)
	if err := jsonWriter.WriteFinding(finding); err != nil || jsonWriter.Close() != nil {
		t.Fatal("JSON writer failed")
	}
	var csvBuf bytes.Buffer
	csvWriter := NewCSVWriter(&csvBuf, nil)
	if err := csvWriter.WriteFinding(finding); err != nil || csvWriter.Close() != nil {
		t.Fatal("CSV writer failed")
	}
	var mdBuf bytes.Buffer
	mdWriter := NewMarkdownWriter(&mdBuf, nil)
	if err := mdWriter.WriteFinding(finding); err != nil || mdWriter.Close() != nil {
		t.Fatal("Markdown writer failed")
	}
	var htmlBuf bytes.Buffer
	htmlWriter, err := NewHTMLWriter(&htmlBuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := htmlWriter.WriteFinding(finding); err != nil || htmlWriter.Close() != nil {
		t.Fatal("HTML writer failed")
	}
	for name, report := range map[string]string{
		"json": jsonBuf.String(), "csv": csvBuf.String(), "markdown": mdBuf.String(), "html": htmlBuf.String(),
	} {
		if !strings.Contains(report, "BEGIN-P6-EVIDENCE") || !strings.Contains(report, "END-P6-EVIDENCE") || strings.Count(report, "SENTINEL-0123456789") < 80 {
			t.Fatalf("%s report mutated long evidence: markers=%v sentinel_count=%d", name, strings.Contains(report, "BEGIN-P6-EVIDENCE") && strings.Contains(report, "END-P6-EVIDENCE"), strings.Count(report, "SENTINEL-0123456789"))
		}
	}
}

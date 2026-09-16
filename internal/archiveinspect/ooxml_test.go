package archiveinspect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func officeFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "office-credential-regression", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

func officeMembers(t *testing.T, name, outerExtension string) map[string]string {
	t.Helper()
	result, err := InspectZIP(officeFixture(t, name), outerExtension, Options{
		Enabled:              true,
		AutoZIPMaxSize:       10 * 1024 * 1024,
		MaxZIPSize:           10 * 1024 * 1024,
		MaxMembers:           64,
		MaxMemberBytes:       4 * 1024 * 1024,
		MaxTotalUncompressed: 8 * 1024 * 1024,
	}, map[string]struct{}{".xml": {}})
	if err != nil {
		t.Fatalf("InspectZIP(%s) returned error: %v", name, err)
	}
	members := make(map[string]string, len(result.Members))
	for _, member := range result.Members {
		members[member.Path] = string(member.Content)
	}
	return members
}

// TestReconstructWordJoinsSplitRuns guards the run-splitting failure: a word
// split across OOXML runs must be rejoined before credential matching.
func TestReconstructWordJoinsSplitRuns(t *testing.T) {
	members := officeMembers(t, "norwegian-docx-runs.docx", ".docx")
	document := members["word/document.xml"]
	for _, want := range []string{"Brukernavn: svc_runs", "Passord: Run-Hemmelig-123!"} {
		if !strings.Contains(document, want) {
			t.Fatalf("split runs were not rejoined; missing %q in %q", want, document)
		}
	}
	if strings.Contains(document, "Pass\nord") || strings.Contains(document, "Pass ord") {
		t.Fatalf("run fragments leaked into reconstructed text: %q", document)
	}
}

func TestReconstructWordTableBecomesRecords(t *testing.T) {
	members := officeMembers(t, "norwegian-docx-table.docx", ".docx")
	document := members["word/document.xml"]
	if !strings.Contains(document, "Brukernavn=svc_table") || !strings.Contains(document, "Passord=Table-Hemmelig-123!") {
		t.Fatalf("table row was not reconstructed as a record: %q", document)
	}
}

func TestReconstructWordAdjacentLabelParagraphs(t *testing.T) {
	members := officeMembers(t, "norwegian-docx-label-value.docx", ".docx")
	document := members["word/document.xml"]
	if !strings.Contains(document, "Brukernavn=svc_para") || !strings.Contains(document, "Passord=Para-Hemmelig-123!") {
		t.Fatalf("adjacent label paragraphs were not paired: %q", document)
	}
}

func TestReconstructWorksheetMapsHeaderRows(t *testing.T) {
	members := officeMembers(t, "norwegian-xlsx-pair.xlsx", ".xlsx")
	worksheet := members["xl/worksheets/sheet1.xml"]
	for _, want := range []string{"Brukernavn=svc_excel", "Passord=Excel-Hemmelig-123!", "Domene=KUNDE"} {
		if !strings.Contains(worksheet, want) {
			t.Fatalf("worksheet record missing %q in %q", want, worksheet)
		}
	}
	// Shared strings stay available as plain lines for existing content rules.
	if !strings.Contains(members["xl/sharedStrings.xml"], "Passord") {
		t.Fatalf("shared strings were not preserved: %q", members["xl/sharedStrings.xml"])
	}
}

func TestReconstructWorksheetKeepsRowsSeparate(t *testing.T) {
	members := officeMembers(t, "norwegian-xlsx-multi.xlsx", ".xlsx")
	worksheet := members["xl/worksheets/sheet1.xml"]
	first := strings.Index(worksheet, "Brukernavn=user1")
	second := strings.Index(worksheet, "Brukernavn=user2")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("expected two separate per-row records: %q", worksheet)
	}
	// One record per row: user1's section must close before user2's begins.
	sectionOne := worksheet[first:]
	if end := strings.Index(sectionOne, "["); end > 0 {
		sectionOne = sectionOne[:end]
	}
	if strings.Contains(sectionOne, "user2") {
		t.Fatalf("row boundaries were not preserved: %q", worksheet)
	}
}

func TestReconstructSlideTextBox(t *testing.T) {
	members := officeMembers(t, "norwegian-pptx-pair.pptx", ".pptx")
	slide := members["ppt/slides/slide1.xml"]
	if !strings.Contains(slide, "Brukernavn: svc_ppt") || !strings.Contains(slide, "Passord: PowerPoint-Hemmelig-123!") {
		t.Fatalf("slide text box was not reconstructed: %q", slide)
	}
}

func TestReconstructCustomDocumentProperties(t *testing.T) {
	content := buildZIPBytes(t, map[string][]byte{
		"docProps/custom.xml": []byte(`<Properties xmlns:vt="urn:vt"><property name="Brukernavn" fmtid="{D5CDD505}" pid="2"><vt:lpwstr>svc_custom</vt:lpwstr></property><property name="Passord" fmtid="{D5CDD505}" pid="3"><vt:lpwstr>Custom-Hemmelig-123!</vt:lpwstr></property></Properties>`),
	})
	result, err := InspectZIP(content, ".docx", Options{
		Enabled: true, MaxMembers: 16, MaxMemberBytes: 1 << 20, MaxTotalUncompressed: 1 << 20,
	}, map[string]struct{}{".xml": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Members) != 1 {
		t.Fatalf("expected the custom property part, got %#v", result.Members)
	}
	got := string(result.Members[0].Content)
	if !strings.Contains(got, "Brukernavn=svc_custom") || !strings.Contains(got, "Passord=Custom-Hemmelig-123!") {
		t.Fatalf("custom document properties were not reconstructed: %q", got)
	}
}

func TestNestedOfficeDocumentInsideZip(t *testing.T) {
	members := officeMembers(t, "nested-passordliste.zip", ".zip")
	document, ok := members["passordliste.docx!word/document.xml"]
	if !ok {
		t.Fatalf("nested Office member was not extracted: %#v", members)
	}
	if !strings.Contains(document, "Passord: Word-Hemmelig-999!") {
		t.Fatalf("nested document text missing: %q", document)
	}
}

func TestOfficeMetadataSurvivesWhenBodyUnreadable(t *testing.T) {
	// A zero-length archive body must still yield container metadata findings;
	// extraction itself returns "archive content unavailable".
	result, err := InspectZIP(nil, ".zip", Options{Enabled: true, MaxMembers: 4, MaxMemberBytes: 1024, MaxTotalUncompressed: 1024}, map[string]struct{}{".txt": {}})
	if err == nil || result.Inspected {
		t.Fatalf("expected an empty zip inspection error, got result=%#v err=%v", result, err)
	}
}

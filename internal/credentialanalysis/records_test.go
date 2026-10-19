package credentialanalysis

import (
	"strings"
	"testing"
)

func TestRenderTableTextHeaderRowsAreSeparateRecords(t *testing.T) {
	rendered := RenderTableText([][]string{
		{"Brukernavn", "Passord", "Domene"},
		{"user1", "Secret1-Norsk!", "KUNDE"},
		{"user2", "Secret2-Norsk!", "KUNDE"},
	}, "worksheet")
	if strings.Count(rendered, "[worksheet record ") != 2 {
		t.Fatalf("expected one section per row, got %q", rendered)
	}
	for _, want := range []string{
		"Brukernavn=user1", "Passord=Secret1-Norsk!", "Domene=KUNDE",
		"Brukernavn=user2", "Passord=Secret2-Norsk!", "Domene=KUNDE",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in %q", want, rendered)
		}
	}
	// Row one must close before row two opens so accounts cannot cross-pair.
	firstRecord := rendered[strings.Index(rendered, "[worksheet record 1]"):strings.Index(rendered, "[worksheet record 2]")]
	if strings.Contains(firstRecord, "user2") || strings.Contains(firstRecord, "Secret2-Norsk!") {
		t.Fatalf("row boundaries not enforced: %q", firstRecord)
	}
}

func TestRenderTableTextLabelValueRows(t *testing.T) {
	rendered := RenderTableText([][]string{
		{"Brukernavn", "svc_excel"},
		{"Passord", "Excel-Hemmelig-123!"},
		{"Domene", "KUNDE"},
	}, "worksheet")
	if strings.Count(rendered, "record ") != 1 {
		t.Fatalf("expected a single label/value record, got %q", rendered)
	}
	for _, want := range []string{"Brukernavn=svc_excel", "Passord=Excel-Hemmelig-123!", "Domene=KUNDE"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in %q", want, rendered)
		}
	}
}

func TestRenderTableTextRejectsUnstructuredInput(t *testing.T) {
	if got := RenderTableText([][]string{{"only one column"}}, "x"); got != "" {
		t.Fatalf("single-column table should not render records, got %q", got)
	}
	if got := RenderTableText([][]string{{"alpha", "beta", "gamma"}, {"1", "2", "3"}}, "x"); got != "" {
		t.Fatalf("unrecognized header row should not render records, got %q", got)
	}
}

func TestParseDelimitedTextDetectsDelimiters(t *testing.T) {
	for _, test := range []struct {
		name  string
		text  string
		width int
	}{
		{"comma", "Brukernavn,Passord,Domene\nsvc,Csv-Hemmelig-123!,KUNDE\n", 3},
		{"semicolon", "Brukernavn;Passord;Domene\nsvc;Semikolon-123!;KUNDE\n", 3},
		{"tab", "Brukernavn\tPassord\tDomene\nsvc\tTab-123!\tKUNDE\n", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows, ok := ParseDelimitedText(test.text)
			if !ok {
				t.Fatalf("delimiter not detected in %q", test.text)
			}
			if len(rows) != 2 || len(rows[0]) != test.width {
				t.Fatalf("unexpected rows: %#v", rows)
			}
		})
	}
	if _, ok := ParseDelimitedText("just a sentence without separators\nand another line\n"); ok {
		t.Fatal("plain text should not parse as delimited")
	}
}

func TestHarvestCSVNorwegianRows(t *testing.T) {
	got := Harvest(HarvestInput{
		Content: []byte("Brukernavn,Passord,Domene\nsvc_csv,Csv-Hemmelig-123!,KUNDE\n"),
		Path:    "credentials.csv",
	})
	if !hasCandidatePayload(got, Confirmed, "Csv-Hemmelig-123!", "svc_csv", "KUNDE") {
		t.Fatalf("CSV Norwegian row was not confirmed: %#v", got)
	}
}

func TestHarvestTSVNorwegianRows(t *testing.T) {
	got := Harvest(HarvestInput{
		Content: []byte("Brukernavn\tPassord\tDomene\nsvc_tsv\tTsv-Hemmelig-123!\tKUNDE\n"),
		Path:    "credentials.tsv",
	})
	if !hasCandidatePayload(got, Confirmed, "Tsv-Hemmelig-123!", "svc_tsv", "KUNDE") {
		t.Fatalf("TSV Norwegian row was not confirmed: %#v", got)
	}
}

func TestHarvestCSVPolicyMetadataIsNotACredential(t *testing.T) {
	got := Harvest(HarvestInput{
		Content: []byte("Setting,Value\nPassordPolicy,Strong\n"),
		Path:    "policy.csv",
	})
	if len(got) != 0 {
		t.Fatalf("CSV policy metadata produced credential candidates: %#v", got)
	}
}

func TestHarvestHTMLCredentialTextKeepsLabelsAndUnescapesValues(t *testing.T) {
	got := Harvest(HarvestInput{
		Content: []byte(`<html><body><table><tr><th>Username</th><th>Password</th></tr><tr><td>svc-html</td><td>Html&amp;Pass-482!</td></tr></table></body></html>`),
		Path:    "credentials.html",
	})
	if !hasCandidatePayload(got, Confirmed, "Html&Pass-482!", "svc-html", "") {
		t.Fatalf("HTML credential was not surfaced from rendered text: %#v", got)
	}
}

func TestHarvestMarkdownCredentialTableKeepsRowsSeparate(t *testing.T) {
	got := Harvest(HarvestInput{
		Content: []byte("| Username | Password |\n| --- | --- |\n| alice | Alice-Pass! |\n| bob | Bob-Pass! |\n"),
		Path:    "credentials.md",
	})
	if !hasCandidatePayload(got, Confirmed, "Alice-Pass!", "alice", "") || !hasCandidatePayload(got, Confirmed, "Bob-Pass!", "bob", "") {
		t.Fatalf("Markdown table credentials were not kept row-scoped: %#v", got)
	}
}

func TestNeedsContentIncludesDocumentAndDelimitedCredentialFormats(t *testing.T) {
	for _, path := range []string{"credentials.csv", "credentials.tsv", "credentials.html", "credentials.htm", "credentials.markdown", "credentials.bat", "credentials.cmd"} {
		if !NeedsContent(path, path, 128) {
			t.Errorf("%s should be eligible for credential content inspection", path)
		}
	}
}

func TestHarvestWindowsBatchLiteralAssignmentsPreserveScopeAndUnicode(t *testing.T) {
	content := "@echo off\r\nset APP_USER=svc-batch\r\nset \"APP_PASS=Åpen-Batch-482!\"\r\nset OTHER_USER=unrelated\r\nset OTHER_PASS=%UNRESOLVED_PASS%\r\n"
	got := Harvest(HarvestInput{Content: []byte(content), Path: "credentials.cmd"})
	if !hasCandidatePayload(got, Confirmed, "Åpen-Batch-482!", "svc-batch", "") {
		t.Fatalf("expected scoped literal batch credential, got %#v", got)
	}
	for _, candidate := range got {
		if candidate.Identity == "unrelated" && candidate.Value == "%UNRESOLVED_PASS%" {
			t.Fatalf("dynamic batch value was incorrectly paired: %#v", candidate)
		}
	}
}

func TestHarvestWindowsBatchAssignmentsDoNotCrossPairPrefixes(t *testing.T) {
	content := "set FIRST_USER=first-user\nset FIRST_PASS=First-Batch-1!\nset SECOND_USER=second-user\nset SECOND_PASSWORD=Second-Batch-2!\nset ORPHAN_USER=orphan-user\nset UNRELATED_PASS=Unrelated-Batch-3!\n"
	got := Harvest(HarvestInput{Content: []byte(content), Path: "credentials.bat"})
	if !hasCandidatePayload(got, Confirmed, "First-Batch-1!", "first-user", "") {
		t.Fatalf("expected first batch credential, got %#v", got)
	}
	if !hasCandidatePayload(got, Confirmed, "Second-Batch-2!", "second-user", "") {
		t.Fatalf("expected second batch credential, got %#v", got)
	}
	for _, candidate := range got {
		if candidate.Verification == Confirmed && candidate.Identity == "orphan-user" {
			t.Fatalf("orphan batch identity was incorrectly paired: %#v", got)
		}
	}
}

func hasCandidatePayload(candidates []Candidate, verification Verification, value, identity, domain string) bool {
	for _, candidate := range candidates {
		if candidate.Value != value || candidate.Verification != verification {
			continue
		}
		if identity != "" && candidate.Identity != identity {
			continue
		}
		if domain != "" && candidate.Domain != domain {
			continue
		}
		return true
	}
	return false
}

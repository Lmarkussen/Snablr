package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snablr/internal/credentialanalysis"
	"snablr/internal/officefixture"
	"snablr/internal/rules"
	"snablr/internal/state"
	"snablr/internal/wiminspect"
	"snablr/pkg/logx"
)

func requireWIM(t *testing.T) string {
	t.Helper()
	wimlib, err := exec.LookPath("wimlib-imagex")
	if err != nil {
		t.Skip("wimlib-imagex not available")
	}
	return wimlib
}

// wimOfficeDocs describes the Office documents placed into one WIM image.
type wimOfficeDocs struct {
	passordliste []byte
	credentials  []byte
	ordinary     []byte
}

func wimOfficeImageOne() wimOfficeDocs {
	return wimOfficeDocs{
		passordliste: officefixture.DOCX(
			officefixture.Paragraph("Brukernavn: svc_wim_word"),
			officefixture.Paragraph("Domene: KUNDE"),
			officefixture.Paragraph("Passord: Wim-Word-Hemmelig-123!"),
		),
		credentials: officefixture.XLSX([][]string{
			{"Brukernavn", "Passord", "Domene"},
			{"svc_wim_xls", "Wim-Excel-Hemmelig-456!", "KUNDE"},
		}),
		ordinary: officefixture.DOCX(officefixture.Paragraph("Kvartalsrapport for markedet.")),
	}
}

func wimOfficeImageTwo() wimOfficeDocs {
	return wimOfficeDocs{
		passordliste: officefixture.DOCX(
			officefixture.Paragraph("Brukernavn: svc_wim_index2"),
			officefixture.Paragraph("Passord: Wim-Index2-Hemmelig-789!"),
		),
		credentials: officefixture.XLSX([][]string{
			{"Brukernavn", "Passord"},
			{"svc_wim_index2_xls", "Wim-Index2-Excel-890!"},
		}),
		ordinary: officefixture.DOCX(officefixture.Paragraph("Ingen hemmeligheter her.")),
	}
}

func writeWIMOfficeSource(t *testing.T, root string, docs wimOfficeDocs) {
	t.Helper()
	files := map[string][]byte{
		filepath.Join("Docs", "passordliste.docx"):   docs.passordliste,
		filepath.Join("Finance", "credentials.xlsx"): docs.credentials,
		filepath.Join("General", "ordinary.docx"):    docs.ordinary,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func captureWIM(t *testing.T, wimlib, sourceDir, wimPath, name string) {
	t.Helper()
	cmd := exec.Command(wimlib, "capture", sourceDir, wimPath, name, "--compress=none")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create WIM: %v\n%s", err, output)
	}
}

func appendWIMImage(t *testing.T, wimlib, sourceDir, wimPath, name string) {
	t.Helper()
	cmd := exec.Command(wimlib, "append", sourceDir, wimPath, name, "--compress=none")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("append WIM image: %v\n%s", err, output)
	}
}

func evaluateWIMFile(t *testing.T, manager *rules.Manager, wimPath string, opts wiminspect.Options) (Evaluation, []credentialanalysis.Candidate) {
	t.Helper()
	content, err := os.ReadFile(wimPath)
	if err != nil {
		t.Fatal(err)
	}
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{WIM: opts}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		Host: "fileserver", Share: "share",
		FilePath: "backup.wim", Name: "backup.wim", Extension: ".wim", Size: int64(len(content)),
	}, content)
	if evaluation.Cleanup != nil {
		t.Cleanup(func() { _ = evaluation.Cleanup() })
	}
	return evaluation, collector.candidates
}

func wimOptionsFor(t *testing.T, wimPath string) wiminspect.Options {
	t.Helper()
	info, err := os.Stat(wimPath)
	if err != nil {
		t.Fatal(err)
	}
	return wiminspect.Options{
		Enabled:        true,
		AutoWIMMaxSize: info.Size() + 1,
		MaxWIMSize:     info.Size() + 1,
	}
}

func candidatePathForValue(candidates []credentialanalysis.Candidate, value string) string {
	for _, candidate := range candidates {
		if candidate.Value == value {
			return candidate.Path
		}
	}
	return ""
}

// TestEngineHarvestsOfficeCredentialsFromWIM covers the WIM coverage gap: an
// interesting Office document inside an image is extracted through the existing
// targeted WIM inspection and then flows through the shared OOXML + credential
// pipeline without any manual extraction step.
func TestEngineHarvestsOfficeCredentialsFromWIM(t *testing.T) {
	wimlib := requireWIM(t)
	manager := loadOfficeRules(t)

	source := t.TempDir()
	writeWIMOfficeSource(t, source, wimOfficeImageOne())
	wimPath := filepath.Join(t.TempDir(), "backup.wim")
	captureWIM(t, wimlib, source, wimPath, "Office Credential Regression")

	evaluation, candidates := evaluateWIMFile(t, manager, wimPath, wimOptionsFor(t, wimPath))
	if evaluation.Skipped {
		t.Fatalf("WIM unexpectedly skipped: %s", evaluation.SkipReason)
	}
	if !hasCandidateValue(candidates, "Wim-Word-Hemmelig-123!", "svc_wim_word", "KUNDE", credentialanalysis.Confirmed) {
		t.Fatalf("DOCX credential inside WIM was not surfaced: %#v", candidates)
	}
	if !hasCandidateValue(candidates, "Wim-Excel-Hemmelig-456!", "svc_wim_xls", "KUNDE", credentialanalysis.Confirmed) {
		t.Fatalf("XLSX credential inside WIM was not surfaced: %#v", candidates)
	}
	for _, candidate := range candidates {
		if strings.Contains(candidate.Path, "ordinary.docx") || strings.Contains(candidate.Source, "ordinary.docx") {
			t.Fatalf("ordinary WIM Office document produced a credential candidate: %#v", candidate)
		}
	}

	docxPath := candidatePathForValue(candidates, "Wim-Word-Hemmelig-123!")
	if !strings.Contains(docxPath, "[index=1]!Docs/passordliste.docx!word/document.xml") {
		t.Fatalf("WIM DOCX provenance missing image index or member path: %q", docxPath)
	}
	xlsxPath := candidatePathForValue(candidates, "Wim-Excel-Hemmelig-456!")
	if !strings.Contains(xlsxPath, "[index=1]!Finance/credentials.xlsx!xl/worksheets/sheet1.xml") {
		t.Fatalf("WIM XLSX provenance missing image index or member path: %q", xlsxPath)
	}
	if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
		t.Fatalf("WIM Office filename discovery missing: %#v", ruleIDs(evaluation.Findings))
	}
	for _, candidate := range candidates {
		if candidate.Container != "" && !strings.Contains(candidate.Container, "backup.wim") {
			t.Fatalf("unexpected container provenance: %#v", candidate)
		}
	}
}

// TestEngineHarvestsOfficeCredentialsFromMultiIndexWIM verifies that image
// provenance is preserved per image and that images are not cross-associated.
func TestEngineHarvestsOfficeCredentialsFromMultiIndexWIM(t *testing.T) {
	wimlib := requireWIM(t)
	manager := loadOfficeRules(t)

	firstSource := t.TempDir()
	writeWIMOfficeSource(t, firstSource, wimOfficeImageOne())
	wimPath := filepath.Join(t.TempDir(), "multi.wim")
	captureWIM(t, wimlib, firstSource, wimPath, "Index One")

	secondSource := t.TempDir()
	writeWIMOfficeSource(t, secondSource, wimOfficeImageTwo())
	appendWIMImage(t, wimlib, secondSource, wimPath, "Index Two")

	_, candidates := evaluateWIMFile(t, manager, wimPath, wimOptionsFor(t, wimPath))
	if !hasCandidateValue(candidates, "Wim-Word-Hemmelig-123!", "svc_wim_word", "KUNDE", credentialanalysis.Confirmed) {
		t.Fatalf("image 1 DOCX credential missing: %#v", candidates)
	}
	if !hasCandidateValue(candidates, "Wim-Index2-Hemmelig-789!", "svc_wim_index2", "", credentialanalysis.Confirmed) {
		t.Fatalf("image 2 DOCX credential missing: %#v", candidates)
	}
	if !hasCandidateValue(candidates, "Wim-Index2-Excel-890!", "svc_wim_index2_xls", "", credentialanalysis.Confirmed) {
		t.Fatalf("image 2 XLSX credential missing: %#v", candidates)
	}

	indexOne := candidatePathForValue(candidates, "Wim-Word-Hemmelig-123!")
	indexTwo := candidatePathForValue(candidates, "Wim-Index2-Hemmelig-789!")
	if !strings.Contains(indexOne, "[index=1]") {
		t.Fatalf("image 1 provenance lost its index: %q", indexOne)
	}
	if !strings.Contains(indexTwo, "[index=2]") {
		t.Fatalf("image 2 provenance lost its index: %q", indexTwo)
	}
	if strings.Contains(indexTwo, "svc_wim_word") || strings.Contains(indexOne, "svc_wim_index2") {
		t.Fatalf("image indexes were cross-associated: %q / %q", indexOne, indexTwo)
	}
}

// TestWIMOfficeIncrementalBehavior validates run-to-run behavior for a changed
// WIM and confirms no credential value is persisted into incremental state.
func TestWIMOfficeIncrementalBehavior(t *testing.T) {
	wimlib := requireWIM(t)
	manager := loadOfficeRules(t)
	workDir := t.TempDir()
	wimPath := filepath.Join(workDir, "incremental.wim")

	firstSource := filepath.Join(workDir, "source-one")
	if err := os.MkdirAll(firstSource, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWIMOfficeSource(t, firstSource, wimOfficeImageOne())
	captureWIM(t, wimlib, firstSource, wimPath, "Incremental")

	inventory, err := state.OpenInventory(filepath.Join(workDir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := func() state.FileObservation {
		info, statErr := os.Stat(wimPath)
		if statErr != nil {
			t.Fatal(statErr)
		}
		return state.FileObservation{Server: "fileserver", Share: "share", Path: "backup.wim", Size: info.Size(), ModifiedAt: info.ModTime().UTC()}
	}

	// RUN 1: first observation must be inspected.
	decision, err := inventory.Prepare(observation(), "ctx-1", "wim-office-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatalf("first run skipped unexpectedly: %s", decision.Reason)
	}
	_, firstCandidates := evaluateWIMFile(t, manager, wimPath, wimOptionsFor(t, wimPath))
	if !hasCandidateValue(firstCandidates, "Wim-Word-Hemmelig-123!", "svc_wim_word", "KUNDE", credentialanalysis.Confirmed) {
		t.Fatalf("run 1 WIM Office credential missing: %#v", firstCandidates)
	}
	inventory.MarkCompleted(decision.Key)
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}

	// RUN 2: unchanged WIM follows existing incremental behavior.
	second, err := inventory.Prepare(observation(), "ctx-1", "wim-office-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Skip || !strings.Contains(second.Reason, "unchanged") {
		t.Fatalf("unchanged WIM was not reused: skip=%v reason=%q", second.Skip, second.Reason)
	}

	// RUN 3: changed WIM must be inspected again and must not reuse the old value.
	changedSource := filepath.Join(workDir, "source-two")
	if err := os.MkdirAll(changedSource, 0o755); err != nil {
		t.Fatal(err)
	}
	changed := wimOfficeImageOne()
	changed.passordliste = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn: svc_wim_word"),
		officefixture.Paragraph("Domene: KUNDE"),
		officefixture.Paragraph("Passord: Wim-Word-CHANGED-999!"),
	)
	writeWIMOfficeSource(t, changedSource, changed)
	captureWIM(t, wimlib, changedSource, wimPath, "Incremental Changed")
	// Force a distinct timestamp so the change is unambiguous regardless of
	// filesystem timestamp granularity.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(wimPath, future, future); err != nil {
		t.Fatal(err)
	}

	third, err := inventory.Prepare(observation(), "ctx-1", "wim-office-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if third.Skip {
		t.Fatalf("changed WIM was skipped: %s", third.Reason)
	}
	_, changedCandidates := evaluateWIMFile(t, manager, wimPath, wimOptionsFor(t, wimPath))
	if !hasCandidateValue(changedCandidates, "Wim-Word-CHANGED-999!", "svc_wim_word", "KUNDE", credentialanalysis.Confirmed) {
		t.Fatalf("changed WIM credential missing: %#v", changedCandidates)
	}
	if hasCandidateValue(changedCandidates, "Wim-Word-Hemmelig-123!", "", "", "") {
		t.Fatalf("old WIM credential value was incorrectly reused: %#v", changedCandidates)
	}
	inventory.MarkCompleted(third.Key)
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(workDir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Wim-Word-Hemmelig-123!", "Wim-Word-CHANGED-999!", "Wim-Excel-Hemmelig-456!"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("incremental state persisted a credential value: %s", secret)
		}
	}
}

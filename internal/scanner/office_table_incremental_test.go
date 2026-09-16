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
	"snablr/internal/state"
	"snablr/pkg/logx"
)

// TestHeaderRowTablePostScanHasNoWeakerDuplicates confirms the logical dedup
// result for a header-row table: exactly one Confirmed record per row and no
// weaker Review copy of the same credential.
func TestHeaderRowTablePostScanHasNoWeakerDuplicates(t *testing.T) {
	manager := loadOfficeRules(t)
	evaluation, candidates := evaluateOfficeFixture(t, manager, "table-a-mixed.docx", true)
	report := credentialanalysis.Analyze(candidates)
	if len(report.Confirmed) != 2 || len(report.Review) != 0 {
		t.Fatalf("expected 2 confirmed and 0 review records, got %d/%d: %#v", len(report.Confirmed), len(report.Review), report)
	}
	seen := map[string]int{}
	for _, candidate := range report.Candidates {
		seen[candidate.Value]++
	}
	for value, count := range seen {
		if count != 1 {
			t.Errorf("logical credential %q reported %d times", value, count)
		}
	}
	if !hasRuleID(evaluation.Findings, "content.password_assignment_indicators") {
		t.Errorf("no actionable content finding for the credential table: %v", ruleIDs(evaluation.Findings))
	}
	_ = manager
}

// TestHeaderRowTableIncrementalBehavior validates run-to-run behaviour when the
// credential table changes, and that no credential value is persisted.
func TestHeaderRowTableIncrementalBehavior(t *testing.T) {
	manager := loadOfficeRules(t)
	dir := t.TempDir()
	docPath := filepath.Join(dir, "PasswordList-table.docx")

	firstTable := officefixture.DOCX(officefixture.TableXML(
		[]officefixture.TableCell{officefixture.Cell("USERNAME"), officefixture.Cell("Passord")},
		[]officefixture.TableCell{officefixture.Cell("Bob"), officefixture.Cell("Old-123!")},
	))
	if err := os.WriteFile(docPath, firstTable, 0o600); err != nil {
		t.Fatal(err)
	}

	inventory, err := state.OpenInventory(filepath.Join(dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	observation := func() state.FileObservation {
		info, statErr := os.Stat(docPath)
		if statErr != nil {
			t.Fatal(statErr)
		}
		return state.FileObservation{Server: "fs01", Share: "share", Path: "Dokumenter/PasswordList-table.docx", Size: info.Size(), ModifiedAt: info.ModTime().UTC()}
	}
	evaluate := func(content []byte) []credentialanalysis.Candidate {
		collector := &recordingCandidateSink{}
		engine := NewEngine(Options{}, manager, nil, logx.New("error"))
		engine.SetCredentialCandidateSink(collector)
		engine.EvaluateContext(context.Background(), FileMetadata{
			Host: "fs01", Share: "share", FilePath: "Dokumenter/PasswordList-table.docx",
			Name: "PasswordList-table.docx", Extension: ".docx", Size: int64(len(content)),
		}, content)
		return collector.candidates
	}

	// RUN 1: new object is inspected and the table credential is surfaced.
	decision, err := inventory.Prepare(observation(), "ctx-1", "table-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatalf("first run skipped unexpectedly: %s", decision.Reason)
	}
	if !hasOfficeCandidate(evaluate(firstTable), "Old-123!", "Bob", "") {
		t.Fatal("run 1 did not surface the table credential")
	}
	inventory.MarkCompleted(decision.Key)
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}

	// RUN 2: unchanged file follows existing incremental policy.
	second, err := inventory.Prepare(observation(), "ctx-1", "table-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Skip || !strings.Contains(second.Reason, "unchanged") {
		t.Fatalf("unchanged table document was not reused: skip=%v reason=%q", second.Skip, second.Reason)
	}

	// RUN 3: changed table must be inspected again and must not reuse the old value.
	secondTable := officefixture.DOCX(officefixture.TableXML(
		[]officefixture.TableCell{officefixture.Cell("USERNAME"), officefixture.Cell("Passord")},
		[]officefixture.TableCell{officefixture.Cell("Bob"), officefixture.Cell("New-456!")},
	))
	if err := os.WriteFile(docPath, secondTable, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(docPath, future, future); err != nil {
		t.Fatal(err)
	}
	third, err := inventory.Prepare(observation(), "ctx-1", "table-incremental", false)
	if err != nil {
		t.Fatal(err)
	}
	if third.Skip {
		t.Fatalf("changed table document was skipped: %s", third.Reason)
	}
	changed := evaluate(secondTable)
	if !hasOfficeCandidate(changed, "New-456!", "Bob", "") {
		t.Fatalf("changed table credential was not surfaced: %#v", changed)
	}
	if hasOfficeCandidate(changed, "Old-123!", "", "") {
		t.Fatalf("stale table credential was reused: %#v", changed)
	}
	inventory.MarkCompleted(third.Key)
	if err := inventory.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Old-123!", "New-456!"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("incremental state persisted a credential value: %s", secret)
		}
	}
}

// TestHeaderRowTableInsideWIM proves the table semantics survive nested
// containers with image-index provenance and no cross-row pairing.
func TestHeaderRowTableInsideWIM(t *testing.T) {
	wimlib := requireWIM(t)
	manager := loadOfficeRules(t)

	source := t.TempDir()
	docs := map[string][]byte{
		filepath.Join("Docs", "PasswordList-table.docx"): officefixture.DOCX(officefixture.TableXML(
			[]officefixture.TableCell{officefixture.Cell("USERNAME"), officefixture.Cell("Passord")},
			[]officefixture.TableCell{officefixture.Cell("Bob"), officefixture.Cell("Synthetic-Bob-123!")},
			[]officefixture.TableCell{officefixture.Cell("Jane"), officefixture.Cell("Synthetic-Jane-456!")},
		)),
	}
	for name, content := range docs {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wimPath := filepath.Join(t.TempDir(), "table.wim")
	cmd := exec.Command(wimlib, "capture", source, wimPath, "Table Office Image", "--compress=none")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create WIM: %v\n%s", err, output)
	}

	_, candidates := evaluateWIMFile(t, manager, wimPath, wimOptionsFor(t, wimPath))
	for _, want := range []struct{ identity, value string }{
		{"Bob", "Synthetic-Bob-123!"},
		{"Jane", "Synthetic-Jane-456!"},
	} {
		if !hasOfficeCandidate(candidates, want.value, want.identity, "") {
			t.Fatalf("WIM table credential %s/%s not surfaced: %#v", want.identity, want.value, candidates)
		}
	}
	if len(candidates) != 2 {
		t.Fatalf("expected exactly 2 credentials from the WIM table, got %d: %#v", len(candidates), candidates)
	}
	for _, candidate := range candidates {
		if !strings.Contains(candidate.Path, "[index=1]!Docs/PasswordList-table.docx!word/document.xml") {
			t.Errorf("WIM table provenance lost the image index or member path: %q", candidate.Path)
		}
	}
}

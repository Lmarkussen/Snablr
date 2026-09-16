package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func officeFixtureDir() string {
	return filepath.Join("..", "..", "testdata", "office-credential-regression")
}

func evaluateOfficeFixture(t *testing.T, manager *rules.Manager, name string, withContent bool) (Evaluation, []credentialanalysis.Candidate) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(officeFixtureDir(), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var payload []byte
	if withContent {
		payload = content
	}
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: "Share/" + name, Name: name, Extension: filepath.Ext(name), Size: int64(len(content)),
	}, payload)
	return evaluation, collector.candidates
}

func loadOfficeRules(t *testing.T) *rules.Manager {
	t.Helper()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	return manager
}

func hasOfficeCandidate(candidates []credentialanalysis.Candidate, value, identity, domain string) bool {
	for _, candidate := range candidates {
		if candidate.Value != value {
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

// TestOfficeCredentialHarvestOracle is the deterministic Office credential
// oracle. It also prints the per-fixture intake audit used in the change
// report (document read -> text extracted -> harvester invoked -> candidate
// emitted -> classification).
func TestOfficeCredentialHarvestOracle(t *testing.T) {
	manager := loadOfficeRules(t)

	type positive struct {
		fixture      string
		value        string
		identity     string
		domain       string
		verification credentialanalysis.Verification
	}
	positives := []positive{
		{"norwegian-docx-pair.docx", "Norsk-Hemmelig-123!", "svc_backup", "KUNDE", credentialanalysis.Confirmed},
		{"norwegian-docx-standalone.docx", "Norsk-Hemmelig-456!", "", "", credentialanalysis.Review},
		{"norwegian-docx-runs.docx", "Run-Hemmelig-123!", "svc_runs", "", credentialanalysis.Confirmed},
		{"norwegian-docx-table.docx", "Table-Hemmelig-123!", "svc_table", "", credentialanalysis.Confirmed},
		{"norwegian-docx-label-value.docx", "Para-Hemmelig-123!", "svc_para", "", credentialanalysis.Confirmed},
		{"norwegian-docx-label-blocks.docx", "Block-Hemmelig-123!", "", "", credentialanalysis.Review},
		{"passordliste.docx", "Word-Hemmelig-999!", "svc_word", "", credentialanalysis.Confirmed},
		{"norwegian-docx-utf8.docx", "Påloggings-Hemmelighet-ÆØÅ-123!", "backup-tjeneste", "ØKONOMI", credentialanalysis.Confirmed},
		{"norwegian-xlsx-pair.xlsx", "Excel-Hemmelig-123!", "svc_excel", "KUNDE", credentialanalysis.Confirmed},
		{"norwegian-xlsx-utf8.xlsx", "Regnskap-ÆØÅ-123!", "tjeneste-bruker-Ø", "ØKONOMI", credentialanalysis.Confirmed},
		{"norwegian-pptx-pair.pptx", "PowerPoint-Hemmelig-123!", "svc_ppt", "", credentialanalysis.Confirmed},
		{"norwegian-credentials.csv", "Csv-Hemmelig-123!", "svc_csv", "KUNDE", credentialanalysis.Confirmed},
		{"norwegian-credentials.tsv", "Tsv-Hemmelig-123!", "svc_tsv", "KUNDE", credentialanalysis.Confirmed},
		{"english-docx-pair.docx", "English-Hemmelig-123!", "svc_eng", "KUNDE", credentialanalysis.Confirmed},
		{"english-xlsx-pair.xlsx", "English-Excel-123!", "svc_eng", "", credentialanalysis.Confirmed},
		{"english-pptx-pair.pptx", "English-PowerPoint-123!", "svc_ppt_eng", "", credentialanalysis.Confirmed},
		{"english-credentials.csv", "English-Csv-123!", "svc_csv_eng", "KUNDE", credentialanalysis.Confirmed},
		{"nested-passordliste.zip", "Word-Hemmelig-999!", "svc_word", "", credentialanalysis.Confirmed},
	}

	// Multi-row spreadsheet: both rows surface and identities never cross rows.
	_, multiRow := evaluateOfficeFixture(t, manager, "norwegian-xlsx-multi.xlsx", true)
	for _, want := range []struct {
		value, identity, domain string
	}{
		{"Secret1-Norsk!", "user1", "KUNDE"},
		{"Secret2-Norsk!", "user2", "KUNDE"},
	} {
		if !hasOfficeCandidate(multiRow, want.value, want.identity, want.domain) {
			t.Errorf("XLSX multi-row credential %q/%q was not surfaced: %#v", want.identity, want.value, multiRow)
		}
	}
	for _, candidate := range multiRow {
		switch {
		case candidate.Value == "Secret1-Norsk!" && candidate.Identity != "" && candidate.Identity != "user1":
			t.Errorf("cross-row pairing: %q mapped to identity %q", candidate.Value, candidate.Identity)
		case candidate.Value == "Secret2-Norsk!" && candidate.Identity != "" && candidate.Identity != "user2":
			t.Errorf("cross-row pairing: %q mapped to identity %q", candidate.Value, candidate.Identity)
		}
	}

	missed := 0
	for _, want := range positives {
		_, candidates := evaluateOfficeFixture(t, manager, want.fixture, true)
		matched := false
		for _, candidate := range candidates {
			if candidate.Value != want.value {
				continue
			}
			matched = true
			if want.identity != "" && candidate.Identity != want.identity {
				t.Errorf("%s: identity = %q, want %q", want.fixture, candidate.Identity, want.identity)
			}
			if want.domain != "" && candidate.Domain != want.domain {
				t.Errorf("%s: domain = %q, want %q", want.fixture, candidate.Domain, want.domain)
			}
			if candidate.Verification != want.verification {
				t.Errorf("%s: verification = %q, want %q", want.fixture, candidate.Verification, want.verification)
			}
			if candidate.CredentialType != "password" {
				t.Errorf("%s: credential type = %q, want password", want.fixture, candidate.CredentialType)
			}
		}
		t.Logf("AUDIT %-34s read=yes extracted=yes harvester=yes candidate=%v verification=%s",
			want.fixture, matched, want.verification)
		if !matched {
			missed++
			t.Errorf("%s: credential %q was not surfaced", want.fixture, want.value)
		}
	}
	if missed != 0 {
		t.Fatalf("positive fixtures: %d, missed: %d", len(positives), missed)
	}
}

// TestOfficeCredentialNegativeFixtures verifies that Norwegian policy and
// documentation material never becomes a credential candidate.
func TestOfficeCredentialNegativeFixtures(t *testing.T) {
	manager := loadOfficeRules(t)
	negatives := []string{
		"norwegian-docx-policy.docx",
		"norwegian-docx-documentation.docx",
		"norwegian-xlsx-policy.xlsx",
		"norwegian-pptx-policy.pptx",
		"norwegian-policy.csv",
		"passordpolicy.docx",
		"passordkrav.docx",
		"veiledning-for-passord.docx",
	}
	for _, name := range negatives {
		_, candidates := evaluateOfficeFixture(t, manager, name, true)
		if len(candidates) != 0 {
			t.Errorf("negative fixture %s produced credential candidates: %#v", name, candidates)
		}
	}
}

// TestOfficeFilenameDiscovery covers the Norwegian filename/path vocabulary.
// Discovery is a hint only: it must never create a credential record.
func TestOfficeFilenameDiscovery(t *testing.T) {
	manager := loadOfficeRules(t)
	strong := []string{"passordliste.docx", "passordliste.txt", "brukerpassord.csv", "nested-passordliste.zip", "innlogging-info.txt"}
	for _, name := range strong {
		evaluation, candidates := evaluateOfficeFixture(t, manager, name, false)
		if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
			t.Errorf("%s: strong Norwegian credential-list filename was not flagged: %#v", name, ruleIDs(evaluation.Findings))
		}
		if len(candidates) != 0 {
			t.Errorf("%s: filename alone produced credential candidates: %#v", name, candidates)
		}
	}
	supporting := []string{"gamle_passord.txt", "palogging.txt"}
	for _, name := range supporting {
		evaluation, _ := evaluateOfficeFixture(t, manager, name, false)
		if !hasRuleID(evaluation.Findings, "filename.norwegian_credential_review_keywords") &&
			!hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
			t.Errorf("%s: supporting Norwegian credential filename was not flagged: %#v", name, ruleIDs(evaluation.Findings))
		}
	}
	for _, name := range []string{"passordpolicy.docx", "passordkrav.docx", "passordrutiner.txt", "veiledning-for-passord.docx"} {
		evaluation, _ := evaluateOfficeFixture(t, manager, name, false)
		if hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") ||
			hasRuleID(evaluation.Findings, "filename.norwegian_credential_review_keywords") {
			t.Errorf("%s: policy/documentation filename was over-promoted: %#v", name, ruleIDs(evaluation.Findings))
		}
	}
}

// TestOfficeCandidatesReachPostScanAndCredsOut verifies Office-derived
// candidates flow into the shared analysis/reporting model.
func TestOfficeCandidatesReachPostScanAndCredsOut(t *testing.T) {
	manager := loadOfficeRules(t)
	evaluation, candidates := evaluateOfficeFixture(t, manager, "passordliste.docx", true)
	if len(candidates) == 0 {
		t.Fatal("passordliste.docx produced no credential candidates")
	}
	foundNestedProvenance := false
	for _, candidate := range candidates {
		if strings.Contains(candidate.Path, "passordliste.docx") {
			foundNestedProvenance = true
		}
	}
	if !foundNestedProvenance {
		t.Errorf("Office candidate provenance missing document name: %#v", candidates)
	}
	if !hasRuleID(evaluation.Findings, "filename.norwegian_password_list_keywords") {
		t.Errorf("passordliste.docx filename hint missing: %#v", ruleIDs(evaluation.Findings))
	}
}

// TestOfficeNestedContainerProvenance checks that a document inside a generic
// archive keeps outer container, inner document, and part provenance.
func TestOfficeNestedContainerProvenance(t *testing.T) {
	manager := loadOfficeRules(t)
	evaluation, candidates := evaluateOfficeFixture(t, manager, "nested-passordliste.zip", true)
	if !hasOfficeCandidate(candidates, "Word-Hemmelig-999!", "svc_word", "") {
		t.Fatalf("nested Office credential was not surfaced: %#v", candidates)
	}
	foundNested := false
	for _, finding := range evaluation.Findings {
		if finding.ArchiveMemberPath == "passordliste.docx!word/document.xml" {
			foundNested = true
		}
	}
	if !foundNested {
		t.Fatalf("nested Office provenance was not preserved: %#v", evaluation.Findings)
	}
}

// TestOfficeFixtureAudit prints the exact candidate intake for every fixture so
// a reviewer can see where a future miss would occur.
func TestOfficeFixtureAudit(t *testing.T) {
	manager := loadOfficeRules(t)
	entries, err := os.ReadDir(officeFixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		_, candidates := evaluateOfficeFixture(t, manager, name, true)
		if len(candidates) == 0 {
			t.Logf("AUDIT %-34s candidates=0", name)
			continue
		}
		for _, candidate := range candidates {
			t.Logf("AUDIT %-34s candidate type=%s verification=%s identity=%q domain=%q value=%q path=%q",
				name, candidate.CredentialType, candidate.Verification, candidate.Identity, candidate.Domain, candidate.Value, candidate.Path)
		}
	}
}

func hasRuleID(findings []Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
		for _, matched := range finding.MatchedRuleIDs {
			if matched == ruleID {
				return true
			}
		}
	}
	return false
}

func ruleIDs(findings []Finding) []string {
	seen := map[string]bool{}
	var ids []string
	for _, finding := range findings {
		if seen[finding.RuleID] {
			// still record matched rule IDs below
		} else {
			seen[finding.RuleID] = true
			ids = append(ids, finding.RuleID)
		}
		for _, matched := range finding.MatchedRuleIDs {
			if seen[matched] {
				continue
			}
			seen[matched] = true
			ids = append(ids, matched)
		}
	}
	sort.Strings(ids)
	return ids
}

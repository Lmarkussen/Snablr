package output

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"snablr/internal/config"
	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

// engineCandidatesForOfficeFixture runs the real engine over one Office fixture
// so both evidence paths (content findings and the structured harvester) are
// represented in the analysis input.
func engineCandidatesForOfficeFixture(t *testing.T, fixture string) ([]scanner.Finding, []credentialanalysis.Candidate) {
	t.Helper()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	path := filepath.Join("..", "..", "testdata", "office-credential-regression", fixture)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	collector := &candidateSink{}
	engine := scanner.NewEngine(scanner.Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), scanner.FileMetadata{
		FilePath: "Docs/" + fixture, Name: fixture, Extension: filepath.Ext(fixture), Size: int64(len(content)),
	}, content)
	return evaluation.Findings, collector.candidates
}

type candidateSink struct {
	candidates []credentialanalysis.Candidate
}

func (s *candidateSink) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	s.candidates = append(s.candidates, candidate)
	return nil
}

// TestOfficeDualPathProducesOneConfirmedRecord is the end-to-end guard against
// the duplicate Confirmed + Review record: the report model must contain exactly
// one logical record per credential per origin.
func TestOfficeDualPathProducesOneConfirmedRecord(t *testing.T) {
	for _, fixture := range []string{"norwegian-docx-pair.docx", "norwegian-docx-utf8.docx", "norwegian-xlsx-pair.xlsx"} {
		findings, candidates := engineCandidatesForOfficeFixture(t, fixture)
		report := analyzeCandidates(findings, candidates)

		confirmedValues := map[string]bool{}
		for _, candidate := range report.Candidates {
			if candidate.Verification == credentialanalysis.Confirmed {
				confirmedValues[candidate.Value] = true
			}
		}
		// A Review record for a value that also has a Confirmed record would be
		// the blocker regression.
		for _, candidate := range report.Candidates {
			if candidate.Verification == credentialanalysis.Confirmed {
				continue
			}
			if confirmedValues[candidate.Value] {
				t.Errorf("%s: value %q appears as both Confirmed and Review", fixture, candidate.Value)
			}
		}
		if len(report.Confirmed) == 0 {
			t.Fatalf("%s: expected confirmed Office credentials, got %#v", fixture, report)
		}
	}
}

// TestOfficeDedupCountsAgreeAcrossReporters compares the logical post-dedup
// model with the sensitive export, JSON metadata, and HTML metadata.
func TestOfficeDedupCountsAgreeAcrossReporters(t *testing.T) {
	const path = "passordliste.docx!word/document.xml"
	candidates := []credentialanalysis.Candidate{
		// Dual path: generic finding (Review) + structured harvester (Confirmed).
		{
			Verification: credentialanalysis.Review, CredentialType: "password", Value: "Norsk-Hemmelig-123!",
			Path: path, ValidationBasis: "credential_like_value_without_conclusive_identity_association",
			ReviewReasons: []string{"identity association ambiguous"},
			Evidence:      []credentialanalysis.Evidence{{RuleID: "content.password_assignment_indicators", Path: path}},
		},
		{
			Verification: credentialanalysis.Confirmed, CredentialType: "password",
			Identity: "svc_backup", Domain: "KUNDE", Value: "Norsk-Hemmelig-123!", Path: path,
			ValidationBasis: "structured configuration section",
			Evidence:        []credentialanalysis.Evidence{{Path: path}},
		},
		// Distinct review-only credential.
		{
			Verification: credentialanalysis.Review, CredentialType: "password", Value: "Egen-Hemmelighet-456!",
			Path: "notes.txt", ReviewReasons: []string{"credential-like value requires semantic review"},
		},
	}
	report := credentialanalysis.Analyze(candidates)
	if len(report.Confirmed) != 1 || len(report.Review) != 1 {
		t.Fatalf("expected 1 confirmed and 1 review record, got %d/%d", len(report.Confirmed), len(report.Review))
	}
	merged := credentialanalysis.Candidate{}
	for _, candidate := range report.Candidates {
		if candidate.Value == "Norsk-Hemmelig-123!" {
			merged = candidate
		}
	}
	if len(merged.Evidence) < 2 {
		t.Fatalf("merged record did not retain both evidence paths: %#v", merged.Evidence)
	}
	if merged.Verification != credentialanalysis.Confirmed {
		t.Fatalf("merged record verification = %q, want confirmed", merged.Verification)
	}

	dir := t.TempDir()
	credsPath := filepath.Join(dir, "creds.txt")
	jsonPath := filepath.Join(dir, "report.json")
	htmlPath := filepath.Join(dir, "report.html")
	writer, err := NewWriter(config.OutputConfig{
		Format: "json,html", NoTUI: true, JSONOut: jsonPath, HTMLOut: htmlPath, CredsOut: credsPath, Pretty: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder, ok := writer.(scanner.CredentialCandidateSink)
	if !ok {
		t.Fatal("writer does not implement the credential candidate sink")
	}
	for _, candidate := range report.Candidates {
		if err := recorder.RecordCredentialCandidate(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	credsRaw, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatal(err)
	}
	credsConfirmed, credsReview := credsCounts(t, string(credsRaw))
	if credsConfirmed != len(report.Confirmed) || credsReview != len(report.Review) {
		t.Fatalf("creds-out counts %d/%d do not match model %d/%d", credsConfirmed, credsReview, len(report.Confirmed), len(report.Review))
	}
	if strings.Count(string(credsRaw), "Norsk-Hemmelig-123!") != 1 {
		t.Fatalf("logical credential rendered more than once in creds-out:\n%s", credsRaw)
	}

	jsonRaw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		CredentialAnalysis struct {
			Confirmed []any `json:"confirmed"`
			Review    []any `json:"review"`
		} `json:"credential_analysis"`
	}
	if err := json.Unmarshal(jsonRaw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.CredentialAnalysis.Confirmed) != len(report.Confirmed) || len(decoded.CredentialAnalysis.Review) != len(report.Review) {
		t.Fatalf("JSON counts %d/%d do not match model %d/%d", len(decoded.CredentialAnalysis.Confirmed), len(decoded.CredentialAnalysis.Review), len(report.Confirmed), len(report.Review))
	}
	if strings.Contains(string(jsonRaw), "Norsk-Hemmelig-123!") {
		t.Fatal("safe JSON leaked a candidate value")
	}

	htmlRaw, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	htmlConfirmed, htmlReview := htmlCounts(t, string(htmlRaw))
	if htmlConfirmed != len(report.Confirmed) || htmlReview != len(report.Review) {
		t.Fatalf("HTML counts %d/%d do not match model %d/%d", htmlConfirmed, htmlReview, len(report.Confirmed), len(report.Review))
	}
	if strings.Contains(string(htmlRaw), "Norsk-Hemmelig-123!") {
		t.Fatal("safe HTML leaked a candidate value")
	}
}

func credsCounts(t *testing.T, output string) (int, int) {
	t.Helper()
	confirmed := parseCountAfter(t, output, "==== CONFIRMED CREDENTIALS ====")
	review := parseCountAfter(t, output, "==== POTENTIAL CREDENTIAL MATERIAL — REVIEW ====")
	return confirmed, review
}

func parseCountAfter(t *testing.T, output, marker string) int {
	t.Helper()
	index := strings.Index(output, marker)
	if index < 0 {
		return 0
	}
	rest := output[index:]
	lineIndex := strings.Index(rest, "Count: ")
	if lineIndex < 0 {
		t.Fatalf("no count line after %q", marker)
	}
	rest = rest[lineIndex+len("Count: "):]
	end := strings.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	value, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		t.Fatalf("invalid count %q: %v", rest[:end], err)
	}
	return value
}

func htmlCounts(t *testing.T, output string) (int, int) {
	t.Helper()
	pattern := regexp.MustCompile(`(?s)card-label">([^<]*)</span>\s*<span class="card-value">(\d+)</span>`)
	confirmed, review := 0, 0
	for _, match := range pattern.FindAllStringSubmatch(output, -1) {
		value, err := strconv.Atoi(match[2])
		if err != nil {
			t.Fatalf("invalid HTML count %q: %v", match[2], err)
		}
		switch {
		case strings.Contains(match[1], "Confirmed Credentials"):
			confirmed = value
		case strings.Contains(match[1], "Potential Credential Material"):
			review = value
		}
	}
	return confirmed, review
}

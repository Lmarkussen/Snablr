package seed

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

type v2CandidateRecorder struct {
	candidates []credentialanalysis.Candidate
}

func (r *v2CandidateRecorder) RecordCredentialCandidate(candidate credentialanalysis.Candidate) error {
	r.candidates = append(r.candidates, candidate)
	return nil
}

// The credential v2 DOCX/XLSX variants previously were not valid OOXML, so
// they measured nothing about Office extraction and every expected pair was
// reported missing. They must be real packages whose expected pairs the
// scanner's Office path recovers.
func TestCredentialCorpusV2OfficeFixturesYieldExpectedPairs(t *testing.T) {
	files, err := Generate(GenerateOptions{CredentialsV2: true, SeedPrefix: "SyntheticSeed", RandomSeed: 1337})
	if err != nil {
		t.Fatalf("generate v2 corpus: %v", err)
	}
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	checked := map[string]int{}
	for _, file := range files {
		if (file.SeedVariant != "docx-member" && file.SeedVariant != "xlsx-member") || file.ExpectedClass != "credential" {
			continue
		}
		engine := scanner.NewEngine(scanner.Options{}, manager, nil, logx.New("error"))
		recorder := &v2CandidateRecorder{}
		engine.SetCredentialCandidateSink(recorder)
		engine.EvaluateContext(context.Background(), scanner.FileMetadata{
			FilePath: FullPath(file), Name: file.Filename, Extension: filepath.Ext(file.Filename), Size: int64(len(file.Content)),
		}, file.Content)

		for _, want := range file.ExpectedPairsDetail {
			found := false
			for _, got := range recorder.candidates {
				if got.Identity == want.Username && got.Value == want.Password {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s (%s): expected pair for %q was not recovered", file.FixtureID, file.SeedVariant, want.Username)
			}
		}
		checked[file.SeedVariant]++
	}
	if checked["docx-member"] == 0 || checked["xlsx-member"] == 0 {
		t.Fatalf("corpus produced no Office credential fixtures to check: %v", checked)
	}
}

// Negative-control reasons label precision results, so each reason must
// describe the content generated for the same index.
func TestCredentialCorpusV2NegativeReasonsMatchContent(t *testing.T) {
	markers := map[string]string{
		"placeholder or masked value":         "CHANGE_ME",
		"unresolved variable":                 "${DEPLOY_PASSWORD}",
		"password-only reference":             "password=orphan-secret",
		"opaque/encrypted material":           "encryptedPassword",
		"random hex unrelated to credentials": "checksum=",
		"password policy documentation":       "Password policy",
		"conflicting independent sections":    "[defaults]",
		"broken connection string":            "postgresql://:missing-user@",
		"empty credential fields":             "username=\npassword=",
	}
	for index := 0; index < len(markers); index++ {
		reason := v2NegativeReason(index)
		marker, ok := markers[reason]
		if !ok {
			t.Fatalf("index %d: unexpected reason %q", index, reason)
		}
		if content := string(v2NegativeContent(index, "svc_synthetic", "Synthetic-1!")); !strings.Contains(content, marker) {
			t.Errorf("index %d: reason %q does not match content %q", index, reason, content)
		}
	}
}

// Full-corpus oracle: the scanner must recover every expected credential v2
// pair from its own source file and must not confirm any pair from a
// negative, review or ambiguous fixture.
func TestCredentialCorpusV2FullPairRecallWithoutConfirmedNegatives(t *testing.T) {
	files, err := Generate(GenerateOptions{CredentialsV2: true, SeedPrefix: "SyntheticSeed", RandomSeed: 1337, MaxFiles: 480})
	if err != nil {
		t.Fatalf("generate v2 corpus: %v", err)
	}
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	manifest := Manifest{}
	var recovered []credentialanalysis.Candidate
	for _, file := range files {
		expectedPath := file.ExpectedPath
		if expectedPath == "" {
			expectedPath = FullPath(file)
		}
		manifest.Entries = append(manifest.Entries, SeedManifestEntry{
			Host: "synthetic-host", Share: "SyntheticShare", Path: expectedPath, FixtureID: file.FixtureID,
			ExpectedPairsDetail: file.ExpectedPairsDetail, ExpectedUsername: file.ExpectedUsername, ExpectedPassword: file.ExpectedPassword,
		})
		engine := scanner.NewEngine(scanner.Options{}, manager, nil, logx.New("error"))
		recorder := &v2CandidateRecorder{}
		engine.SetCredentialCandidateSink(recorder)
		evaluation := engine.EvaluateContext(context.Background(), scanner.FileMetadata{
			Host: "synthetic-host", Share: "SyntheticShare", FilePath: FullPath(file),
			Name: file.Filename, Extension: filepath.Ext(file.Filename), Size: int64(len(file.Content)),
		}, file.Content)
		if len(file.ExpectedPairsDetail) > 0 && !hasActionableFinding(evaluation.Findings) {
			t.Errorf("%s (%s): recovered credential produced no actionable finding: %v", file.FixtureID, file.SeedVariant, findingSummaries(evaluation.Findings))
		}
		for _, candidate := range recorder.candidates {
			candidate.Host, candidate.Share = "synthetic-host", "SyntheticShare"
			if candidate.Path == "" {
				candidate.Path = FullPath(file)
			}
			if len(file.ExpectedPairsDetail) == 0 && candidate.Verification == credentialanalysis.Confirmed && candidate.Identity != "" {
				t.Errorf("%s (%s, %s): confirmed pair for %q on a fixture without expected pairs", file.FixtureID, file.SeedVariant, file.NegativeReason, candidate.Identity)
			}
			recovered = append(recovered, candidate)
		}
	}
	report := VerifyCredentialPairs(manifest, recovered, true)
	if report.ExpectedPairs == 0 || report.MatchedPairs != report.ExpectedPairs {
		for _, missing := range report.Missing {
			t.Errorf("missing expected pair %s (%s)", missing.ID, missing.Path)
		}
		t.Fatalf("pair recall %d/%d", report.MatchedPairs, report.ExpectedPairs)
	}
}

// hasActionableFinding reports whether a recovered credential is visible as a
// primary, actionable finding (from the harvester or a specialised inspector).
func hasActionableFinding(findings []scanner.Finding) bool {
	for _, finding := range findings {
		if finding.Actionable {
			return true
		}
	}
	return false
}

func findingSummaries(findings []scanner.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.RuleID+"/"+finding.TriageClass)
	}
	return out
}

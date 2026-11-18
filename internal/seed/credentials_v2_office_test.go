package seed

import (
	"context"
	"path/filepath"
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

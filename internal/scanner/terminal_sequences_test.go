package scanner

import (
	"context"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/pkg/logx"
)

// Coloured console logs and transcripts embed terminal sequences inside
// otherwise plain assignments. They previously hid credentials from both the
// content rules and the harvester; the recovered values must be clean.
func TestCredentialsInsideTerminalColouredTextAreDetected(t *testing.T) {
	content := "\x1b[32m[INFO]\x1b[0m deployment started\nusername=\x1b[1msvc_colour\x1b[0m\npassword=\x1b[1mSynthetic-Colour-73!\x1b[0m\n"
	engine := NewEngine(Options{}, loadOfficeRules(t), nil, logx.New("error"))
	recorder := &recordingCandidateSink{}
	engine.SetCredentialCandidateSink(recorder)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: "Logs/deploy-console.log", Name: "deploy-console.log", Extension: ".log", Size: int64(len(content)),
	}, []byte(content))

	confirmed := false
	for _, candidate := range recorder.candidates {
		if candidate.Verification == credentialanalysis.Confirmed && candidate.Identity == "svc_colour" && candidate.Value == "Synthetic-Colour-73!" {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("credential inside coloured text not recovered cleanly: %+v", recorder.candidates)
	}
	finding, ok := confirmedCredentialFinding(evaluation.Findings)
	if !ok || !finding.Actionable {
		t.Fatalf("no actionable finding for coloured credential text: %v", ruleIDs(evaluation.Findings))
	}
}

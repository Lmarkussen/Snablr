package scanner

import (
	"context"
	"testing"

	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestEngineKeepsSCCMRecordsSeparateAndSourceScoped(t *testing.T) {
	content := []byte(`{"records":[{"sccmType":"client","siteCode":"ABC","managementPoints":["mp-a","mp-b"]},{"sccmType":"taskSequence","name":"OSD","steps":[{"action":"Install A"},{"action":"Install B"}]}]}`)
	engine := NewEngine(Options{MaxFileSizeBytes: 1024 * 1024, MaxReadBytes: 1024 * 1024}, &rules.Manager{}, nil, logx.New("error"))
	first := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: "sccm.json", Name: "sccm.json", Extension: ".json", Size: int64(len(content))}, content)
	if len(first.Findings) != 4 {
		t.Fatalf("unexpected SCCM finding count: %#v", first.Findings)
	}
	for _, finding := range first.Findings {
		if finding.TriageClass != "weak-review" || finding.SignalType != "content" || finding.Confidence == "high" {
			t.Fatalf("synthetic SCCM contract was overstated: %#v", finding)
		}
	}
	seen := map[string]bool{}
	for _, finding := range first.Findings {
		if finding.ObservationID == "" || seen[finding.ObservationID] {
			t.Fatalf("SCCM observation identity was missing or duplicated: %#v", first.Findings)
		}
		seen[finding.ObservationID] = true
	}
	second := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "other", FilePath: "sccm.json", Name: "sccm.json", Extension: ".json", Size: int64(len(content))}, content)
	if first.Findings[0].ObservationID == second.Findings[0].ObservationID {
		t.Fatal("SCCM source scope was not included in ObservationID")
	}
}

func TestEngineDoesNotCreateSCCMCredentialCandidates(t *testing.T) {
	content := []byte(`<TaskSequence><Name>OSD</Name><Step id="join"><Action>DomainJoin</Action><OSDJoinAccount>synthetic\\join</OSDJoinAccount><OSDJoinPassword>JoinSecret!</OSDJoinPassword></Step></TaskSequence>`)
	engine := NewEngine(Options{MaxFileSizeBytes: 1024 * 1024, MaxReadBytes: 1024 * 1024}, &rules.Manager{}, nil, logx.New("error"))
	first := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: "tasksequence.xml", Name: "tasksequence.xml", Extension: ".xml", Size: int64(len(content))}, content)
	// The SCCM inspector itself only records the task-sequence step as a
	// weak-review contract observation. The explicitly named OSD join account
	// and password are confirmed by the credential harvester, and every
	// confirmed credential is reported as its own finding.
	var step, credential *Finding
	for i := range first.Findings {
		switch first.Findings[i].RuleID {
		case "sccminspect.task_sequence.step":
			step = &first.Findings[i]
		case ConfirmedCredentialRuleID:
			credential = &first.Findings[i]
		default:
			t.Fatalf("unexpected SCCM task-sequence finding %s: %#v", first.Findings[i].RuleID, first.Findings)
		}
	}
	if step == nil || step.TriageClass != "weak-review" || step.Actionable {
		t.Fatalf("SCCM task-sequence step was missing or overstated: %#v", first.Findings)
	}
	if credential == nil || !credential.Actionable {
		t.Fatalf("confirmed OSD join credential was not reported as an actionable finding: %#v", first.Findings)
	}
}

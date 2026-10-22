package scanner

import (
	"context"
	"testing"

	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestEnginePersistsSourceAwareWindowsArtifactObservations(t *testing.T) {
	content := []byte(`<Groups><User name="one"/><User name="two"/></Groups>`)
	engine := NewEngine(Options{MaxFileSizeBytes: 1024 * 1024, MaxReadBytes: 1024 * 1024}, &rules.Manager{}, nil, logx.New("error"))
	first := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: "policies/Groups.xml", Name: "Groups.xml", Extension: ".xml", Size: int64(len(content))}, content)
	if len(first.Findings) != 2 || first.Findings[0].RuleID != "windowsinspect.gpp.groups" || first.Findings[1].RuleID != "windowsinspect.gpp.groups" {
		t.Fatalf("unexpected Windows findings: %#v", first.Findings)
	}
	second := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "other", FilePath: "policies/Groups.xml", Name: "Groups.xml", Extension: ".xml", Size: int64(len(content))}, content)
	if len(second.Findings) != 2 || first.Findings[0].ObservationID == second.Findings[0].ObservationID {
		t.Fatalf("source identity was not included: first=%#v second=%#v", first.Findings, second.Findings)
	}
	again := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: "policies/Groups.xml", Name: "Groups.xml", Extension: ".xml", Size: int64(len(content))}, content)
	if len(again.Findings) != 2 || again.Findings[0].ObservationID != first.Findings[0].ObservationID {
		t.Fatalf("observation identity was not stable: %q != %q", first.Findings[0].ObservationID, again.Findings[0].ObservationID)
	}
}

func TestEngineKeepsRegistryEvidenceComplete(t *testing.T) {
	content := []byte("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\Synthetic]\r\n\"Value\"=\"complete\"\r\n")
	engine := NewEngine(Options{MaxFileSizeBytes: 1024 * 1024, MaxReadBytes: 1024 * 1024}, &rules.Manager{}, nil, logx.New("error"))
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{Host: "host", Share: "share", FilePath: "export.reg", Name: "export.reg", Extension: ".reg", Size: int64(len(content))}, content)
	if len(evaluation.Findings) != 1 {
		t.Fatalf("registry finding missing: %#v", evaluation.Findings)
	}
	if evaluation.Findings[0].MatchedText != string(content) || evaluation.Findings[0].Snippet != string(content) || evaluation.Findings[0].Context != string(content) {
		t.Fatalf("registry evidence was changed: %#v", evaluation.Findings[0])
	}
}

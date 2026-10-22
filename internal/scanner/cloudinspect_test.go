package scanner

import (
	"strings"
	"testing"

	"snablr/internal/cloudinspect"
	"snablr/pkg/logx"
)

func TestCloudFindingsUseStableSourceAwareObservationIDs(t *testing.T) {
	meta := FileMetadata{Host: "host-a", Share: "share", FilePath: "config.json"}
	matches := cloudinspect.New().InspectContent(cloudinspect.Candidate{Name: "config.json", Extension: ".json"}, []byte(`{"type":"external_account","audience":"a","subject_token_type":"jwt","credential_source":{"file":"token"}}`))
	first := findingsFromCloudMatches(meta, matches)
	second := findingsFromCloudMatches(meta, matches)
	if len(first) != 1 || len(second) != 1 || first[0].ObservationID == "" || first[0].ObservationID != second[0].ObservationID {
		t.Fatalf("unstable cloud observation ID: %#v %#v", first, second)
	}
	different := findingsFromCloudMatches(FileMetadata{Host: "host-b", Share: "share", FilePath: "config.json"}, matches)
	if len(different) != 1 || different[0].ObservationID == first[0].ObservationID {
		t.Fatalf("source identity was not included: %q", different[0].ObservationID)
	}
	if !strings.Contains(first[0].MatchedText, "external_account") || first[0].Context == "" {
		t.Fatal("cloud evidence was not retained")
	}
}

func TestEngineEvaluatesCloudArtifactFromExtensionlessJSON(t *testing.T) {
	engine := NewEngine(Options{}, nil, nil, logx.New("error"))
	meta := FileMetadata{Host: "host-a", Share: "share", FilePath: "configs/opaque", Name: "opaque", Size: 180}
	content := []byte(`{"type":"external_account","audience":"audience","subject_token_type":"jwt","credential_source":{"file":"token"}}`)
	evaluation := engine.Evaluate(meta, content)
	if !evaluation.ContentRead || len(evaluation.Findings) == 0 {
		t.Fatalf("extensionless cloud configuration was not inspected: %#v", evaluation)
	}
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "cloudinspect.gcp.external_account" {
			if finding.MatchedText != string(content) || finding.ArchiveMemberPath != "" {
				t.Fatalf("cloud evidence/provenance changed: %#v", finding)
			}
			return
		}
	}
	t.Fatalf("external-account finding missing: %#v", evaluation.Findings)
}

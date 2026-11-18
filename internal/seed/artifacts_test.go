package seed

import (
	"context"
	"path/filepath"
	"testing"

	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/pkg/logx"
)

// Offline oracle for the artifact corpus: every fixture is evaluated the way
// the scanner reads it (whole, by prefix, or not at all above the size limit)
// and must produce its expected rule with the expected actionability.
func TestArtifactCorpusOracle(t *testing.T) {
	files, err := Generate(GenerateOptions{Artifacts: true, SeedPrefix: "SyntheticSeed"})
	if err != nil {
		t.Fatalf("generate artifact corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("artifact corpus is empty")
	}
	manager, _, err := rules.LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	// A 1 MiB limit keeps the oracle fast; the oversized fixtures are just over
	// the scanner's 10 MiB default and exceed it either way.
	const limit = 1024 * 1024
	oversized := 0
	for _, file := range files {
		t.Run(file.FixtureID+"-"+file.Filename, func(t *testing.T) {
			engine := scanner.NewEngine(scanner.Options{MaxFileSizeBytes: limit, MaxReadBytes: limit}, manager, nil, logx.New("error"))
			meta := scanner.FileMetadata{
				Host: "synthetic-host", Share: "SyntheticShare", FilePath: FullPath(file),
				Name: file.Filename, Extension: filepath.Ext(file.Filename), Size: int64(len(file.Content)),
			}
			content := file.Content
			if prefix := engine.PrefixReadLimit(meta); prefix > 0 {
				content = content[:prefix]
			} else if !engine.NeedsContent(meta) {
				content = nil
			}
			evaluation := engine.EvaluateContext(context.Background(), meta, content)

			rule := file.ExpectedRuleThemes[0]
			var matched *scanner.Finding
			anyActionable := false
			for i := range evaluation.Findings {
				finding := &evaluation.Findings[i]
				anyActionable = anyActionable || finding.Actionable
				for _, id := range append([]string{finding.RuleID}, finding.MatchedRuleIDs...) {
					if id == rule {
						matched = finding
					}
				}
			}
			switch file.ExpectedClass {
			case seedClassActionable:
				if matched == nil || !matched.Actionable {
					t.Fatalf("expected actionable %s; findings=%v", rule, findingSummaries(evaluation.Findings))
				}
			case seedClassWeakReview:
				if matched == nil {
					t.Fatalf("expected %s; findings=%v", rule, findingSummaries(evaluation.Findings))
				}
				if anyActionable {
					t.Fatalf("weak-review fixture produced an actionable finding: %v", findingSummaries(evaluation.Findings))
				}
			case "negative":
				if matched != nil || anyActionable {
					t.Fatalf("negative fixture produced %s or an actionable finding: %v", rule, findingSummaries(evaluation.Findings))
				}
			default:
				t.Fatalf("unexpected fixture class %q", file.ExpectedClass)
			}
		})
		if len(file.Content) > limit {
			oversized++
		}
	}
	if oversized == 0 {
		t.Fatal("artifact corpus has no oversized fixtures")
	}
}

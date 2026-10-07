package scanner

import (
	"path/filepath"
	"testing"

	"snablr/internal/rules"
	"snablr/pkg/logx"
)

// TestContentRuleRejectsSQLFragmentValues proves that a credential-like label
// followed by a SQL variable, expression, schema definition or prose fragment
// does not produce a password-assignment finding, while a genuine scalar value
// still does.
func TestContentRuleRejectsSQLFragmentValues(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))

	negatives := []string{
		"Password=@var\n",
		"Password=func(column_a, 1, 2)\n",
		"PASSWORD=field,,type(255)\n",
		"Password=plain words here\n",
	}
	for _, content := range negatives {
		meta := FileMetadata{FilePath: "config/app.ini", Name: "app.ini", Extension: ".ini", Size: int64(len(content))}
		evaluation := engine.Evaluate(meta, []byte(content))
		for _, finding := range evaluation.Findings {
			if finding.RuleID == "content.password_assignment_indicators" {
				t.Fatalf("fragment value %q produced a password finding: %#v", content, finding)
			}
		}
	}

	positive := "Password=Synthetic-Password-123!\n"
	meta := FileMetadata{FilePath: "config/app.ini", Name: "app.ini", Extension: ".ini", Size: int64(len(positive))}
	evaluation := engine.Evaluate(meta, []byte(positive))
	found := false
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "content.password_assignment_indicators" {
			found = true
		}
	}
	if !found {
		t.Fatalf("genuine password assignment did not produce a finding: %#v", evaluation.Findings)
	}
}

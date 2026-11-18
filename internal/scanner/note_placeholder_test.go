package scanner

import (
	"context"
	"strings"
	"testing"

	"snablr/pkg/logx"
)

func noteStyleActionable(t *testing.T, content string) bool {
	t.Helper()
	engine := NewEngine(Options{}, loadOfficeRules(t), nil, logx.New("error"))
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: "Share/IT/notes.txt", Name: "notes.txt", Extension: ".txt", Size: int64(len(content)),
	}, []byte(content))
	for _, finding := range evaluation.Findings {
		for _, ruleID := range append([]string{finding.RuleID}, finding.MatchedRuleIDs...) {
			if ruleID == "content.note_style_credential_pair_indicators" && finding.Actionable {
				return true
			}
		}
	}
	return false
}

// The note-style rule matches the account line. When the paired secret is only
// a placeholder or an unresolved reference there is no credential, so the
// account line alone must not be reported as an actionable credential pair.
func TestNoteStyleRuleIgnoresPlaceholderSecrets(t *testing.T) {
	for name, content := range map[string]string{
		"placeholder": "username=example-user\npassword=CHANGE_ME\nmasked=********\n",
		"variable":    "account=reference-only\npassword=${DEPLOY_PASSWORD}\n",
		"masked":      "login=svc_synthetic\npassword=********\n",
	} {
		if noteStyleActionable(t, content) {
			t.Errorf("%s: note-style finding stayed actionable for a placeholder secret", name)
		}
	}
}

func TestNoteStyleRuleKeepsRealSecretsAndUnpairedNotes(t *testing.T) {
	for name, content := range map[string]string{
		"real secret":          "username=svc_synthetic\npassword=Synthetic-Real-77!\n",
		"real and placeholder": "username=svc_synthetic\npassword=Synthetic-Real-77!\nbackup_password=CHANGE_ME\n",
		"account note only":    "Domain administrator: svc_synthetic_admin\n",
	} {
		if !noteStyleActionable(t, content) {
			t.Errorf("%s: note-style finding was no longer actionable", name)
		}
	}
}

func contentRuleActionable(t *testing.T, ruleID, path, content string) bool {
	t.Helper()
	engine := NewEngine(Options{}, loadOfficeRules(t), nil, logx.New("error"))
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: path, Name: path[strings.LastIndex(path, "/")+1:], Extension: path[strings.LastIndex(path, "."):], Size: int64(len(content)),
	}, []byte(content))
	for _, finding := range evaluation.Findings {
		for _, id := range append([]string{finding.RuleID}, finding.MatchedRuleIDs...) {
			if id == ruleID && finding.Actionable {
				return true
			}
		}
	}
	return false
}

// A password note whose only value is a placeholder or an unresolved
// reference is not a credential; a real value on the same rule still is.
func TestPasswordNoteRuleIgnoresPlaceholderValues(t *testing.T) {
	const rule = "content.password_note_value_indicators"
	for name, content := range map[string]string{
		"variable":    "account=reference-only\npassword=${DEPLOY_PASSWORD}\n",
		"placeholder": "username=example-user\npassword=CHANGE_ME\nmasked=********\n",
	} {
		if contentRuleActionable(t, rule, "Share/database/postgres-uri-1.txt", content) {
			t.Errorf("%s: %s stayed actionable for a placeholder value", name, rule)
		}
	}
	if !contentRuleActionable(t, rule, "Share/database/postgres-uri-2.txt", "password=Synthetic-Real-88!\n") {
		t.Errorf("real password value no longer produced an actionable %s finding", rule)
	}
}

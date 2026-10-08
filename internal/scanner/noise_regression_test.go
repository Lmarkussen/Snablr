package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"

	"snablr/pkg/logx"
)

// Synthetic detector-quality regressions. Every value is independently
// invented and no live/customer/report material is used.

func newNoiseEngine(t *testing.T) *Engine {
	t.Helper()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	return NewEngine(Options{}, manager, nil, logx.New("error"))
}

func evaluateNoise(t *testing.T, engine *Engine, name, content string) []Finding {
	t.Helper()
	meta := FileMetadata{
		FilePath:  "synthetic/" + name,
		Name:      name,
		Extension: filepath.Ext(name),
		Size:      int64(len(content)),
	}
	return engine.Evaluate(meta, []byte(content)).Findings
}

func evaluateNoiseCandidates(t *testing.T, manager *rules.Manager, name, content string) ([]Finding, []credentialanalysis.Candidate) {
	t.Helper()
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, manager, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
		FilePath: "synthetic/" + name, Name: name, Extension: filepath.Ext(name), Size: int64(len(content)),
	}, []byte(content))
	return evaluation.Findings, collector.candidates
}

func findingRuleSet(findings []Finding) map[string]bool {
	set := make(map[string]bool, len(findings))
	for _, finding := range findings {
		set[finding.RuleID] = true
		for _, id := range finding.MatchedRuleIDs {
			set[id] = true
		}
	}
	return set
}

// 5. Bare dictionary/wordlist entries must not produce credential findings.
func TestNoiseDictionaryWordsProduceNoCredentialFindings(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)
	content := "password\n12345678\ncredentials\nsynthetic\nPW\n"
	findings := evaluateNoise(t, engine, "synthetic-wordlist.txt", content)
	for _, ruleID := range []string{
		"content.password_assignment_indicators",
		"content.password_note_value_indicators",
		"content.credential_note_indicators",
		"content.note_style_credential_pair_indicators",
	} {
		if findingRuleSet(findings)[ruleID] {
			t.Errorf("dictionary wordlist triggered %s: %v", ruleID, findingRuleSet(findings))
		}
	}
}

// 6. Path-like labels are not credential pairs.
func TestNoisePathLabelsAreNotCredentialPairs(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)
	content := "AppPath: C:\\Synthetic\\App.exe\nDirectory: C:\\Synthetic\\Data\nLocation: D:\\Synthetic\n"
	findings := evaluateNoise(t, engine, "synthetic-notes.txt", content)
	if findingRuleSet(findings)["content.note_style_credential_pair_indicators"] {
		t.Fatalf("path-like labels were treated as credential pairs: %v", findingRuleSet(findings))
	}
}

// 7. A genuine username/password note is retained.
func TestNoiseCredentialNotePairIsRetained(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)
	content := "Username: synthetic-user\nPassword: Synthetic-Note-932!\n"
	findings := evaluateNoise(t, engine, "synthetic-cred-notes.txt", content)
	set := findingRuleSet(findings)
	if !set["content.note_style_credential_pair_indicators"] {
		t.Errorf("username/password note did not produce a note-style pair: %v", set)
	}
	if !set["content.password_assignment_indicators"] {
		t.Errorf("password line did not produce a password assignment finding: %v", set)
	}
}

// 11. The bare word "Server" is not a connection string.
func TestNoiseServerWordAloneIsNotAConnectionString(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)
	content := `<Registry><Properties name="Server" value="synthetic-host" uid="{00000000-0000-0000-0000-000000000000}" /></Registry>` + "\n"
	findings := evaluateNoise(t, engine, "synthetic-registry.xml", content)
	if findingRuleSet(findings)["content.database_connection_string_indicators"] {
		t.Fatalf("bare word Server produced a connection-string finding: %v", findingRuleSet(findings))
	}
}

// 8/9/10. Empty and masked passwords are not credentials; real ones are.
func TestNoiseConnectionStringPasswordCases(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)

	empty := `ConnectionString=Provider=Synthetic.OLEDB.1;User ID=Admin;Password="";Data Source=C:\Synthetic\data.synthetic;` + "\n"
	masked := `ConnectionString=Server=synthetic.test;User ID=svc_synthetic;Password=********;` + "\n"
	real := `ConnectionString=Server=db.synthetic.test;User ID=svc_synthetic;Password=Synthetic-DB-527!;` + "\n"

	for _, tc := range []struct {
		name, content string
	}{
		{"empty", empty},
		{"masked", masked},
	} {
		findings := evaluateNoise(t, engine, "synthetic-"+tc.name+".config", tc.content)
		set := findingRuleSet(findings)
		if set["dbinspect.access.connection_string"] || set["dbinspect.access.dsn"] {
			t.Errorf("%s password produced a credential finding: %v", tc.name, set)
		}
	}

	findings := evaluateNoise(t, engine, "synthetic-real.config", real)
	if !findingRuleSet(findings)["dbinspect.access.connection_string"] {
		t.Errorf("real connection string did not produce a credential finding: %v", findingRuleSet(findings))
	}
}

// 3. A localization JSON bundle produces no credential finding.
func TestNoiseLocalizationJsonProducesNoCredential(t *testing.T) {
	t.Parallel()
	engine := newNoiseEngine(t)
	content := `{
  "login.title": "Sign in to the synthetic portal",
  "login.error.invalidPassword": "The password you entered is incorrect",
  "login.error.invalidUsername": "The user name is not recognised",
  "_login.error.invalidPassword.comment": "Shown when the supplied password does not match",
  "common.ok": "OK",
  "common.cancel": "Cancel"
}`
	findings := evaluateNoise(t, engine, "synthetic-locale.json", content)
	for _, ruleID := range []string{
		"content.password_assignment_indicators",
		"content.secret_assignment_indicators",
		"content.note_style_credential_pair_indicators",
	} {
		if findingRuleSet(findings)[ruleID] {
			t.Errorf("localization resource triggered %s: %v", ruleID, findingRuleSet(findings))
		}
	}
}

// 4. A structured JSON credential object produces a credential finding.
func TestNoiseStructuredJsonCredentialProducesFinding(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	content := `{"username":"synthetic-user","password":"Synthetic-Json-934!"}`
	_, candidates := evaluateNoiseCandidates(t, manager, "synthetic-cred.json", content)
	if candidateForValue(candidates, "Synthetic-Json-934!") == nil {
		t.Fatalf("structured JSON credential was not recovered: %#v", candidates)
	}
}

// AdminPassword=, SvcPass=, and RUN_PASSWORD= must keep working.
func TestNoiseCompoundPasswordLabelsAreRetained(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	cases := []struct {
		line  string
		value string
	}{
		{"AdminPassword=Synthetic-Admin-123!", "Synthetic-Admin-123!"},
		{"$SvcPass = \"Synthetic-Service-123!\"", "Synthetic-Service-123!"},
		{"export RUN_PASSWORD=Synthetic-Run-123!", "Synthetic-Run-123!"},
	}
	for _, tc := range cases {
		_, candidates := evaluateNoiseCandidates(t, manager, "synthetic-deploy.ps1", tc.line+"\n")
		if candidateForValue(candidates, tc.value) == nil {
			t.Errorf("compound password label %q was not recovered: %#v", strings.TrimSpace(tc.line), candidates)
		}
	}
}

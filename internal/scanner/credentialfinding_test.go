package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"snablr/pkg/logx"
)

func confirmedCredentialFinding(findings []Finding) (Finding, bool) {
	for _, finding := range findings {
		for _, ruleID := range append([]string{finding.RuleID}, finding.MatchedRuleIDs...) {
			if ruleID == ConfirmedCredentialRuleID {
				return finding, true
			}
		}
	}
	return Finding{}, false
}

// Confirmed credential material must always surface as a finding. A CSV
// credential table, for example, matched no content rule, so its recovered
// pair existed only in the persisted credential evidence.
func TestConfirmedCredentialsAlwaysProduceActionableFinding(t *testing.T) {
	manager := loadOfficeRules(t)
	cases := map[string]string{
		"Share/IT/accounts.csv":                       "account,secret,target\nsvc_synthetic,Synthetic-Csv-41!,app.synthetic\n",
		"Share/IT/notes.txt":                          "account=svc_synthetic password=Synthetic-Line-42!\n",
		"Share/Users/a/AppData/Local/Temp/deploy.txt": "user=svc_synthetic\npassword=Synthetic-Temp-43!\n",
	}
	for path, content := range cases {
		t.Run(path, func(t *testing.T) {
			engine := NewEngine(Options{}, manager, nil, logx.New("error"))
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
				FilePath: path, Name: filepath.Base(path), Extension: filepath.Ext(path), Size: int64(len(content)),
			}, []byte(content))
			finding, ok := confirmedCredentialFinding(evaluation.Findings)
			if !ok {
				t.Fatalf("no confirmed-credential finding; findings=%v", ruleIDs(evaluation.Findings))
			}
			// When a content rule also matched, the merged finding's primary is
			// that rule, so the account may be reported with surrounding text.
			if !finding.Actionable || !strings.Contains(finding.PotentialAccount, "svc_synthetic") {
				t.Fatalf("finding not actionable or account missing: actionable=%v account=%q triage=%s", finding.Actionable, finding.PotentialAccount, finding.TriageClass)
			}
		})
	}
}

func TestUnconfirmedMaterialDoesNotProduceConfirmedCredentialFinding(t *testing.T) {
	manager := loadOfficeRules(t)
	cases := map[string]string{
		"Share/IT/encrypted.xml":   "<credential><user>svc_synthetic</user><encryptedPassword>QkFTRTY0LUNJUEhFUlRFWFQ=</encryptedPassword></credential>",
		"Share/IT/placeholder.txt": "username=svc_synthetic\npassword=CHANGE_ME\n",
		"Share/IT/orphan.txt":      "password=orphan-synthetic-secret\n",
	}
	for path, content := range cases {
		t.Run(path, func(t *testing.T) {
			engine := NewEngine(Options{}, manager, nil, logx.New("error"))
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
				FilePath: path, Name: filepath.Base(path), Extension: filepath.Ext(path), Size: int64(len(content)),
			}, []byte(content))
			if _, ok := confirmedCredentialFinding(evaluation.Findings); ok {
				t.Fatalf("unconfirmed material produced a confirmed-credential finding; findings=%v", ruleIDs(evaluation.Findings))
			}
		})
	}
}

package scanner

import (
	"testing"

	"snablr/internal/credentialanalysis"
)

// Usage examples in Python documentation strings are kept as review
// material and are never confirmed or actionable; credentials in the code
// of the same file are unaffected.
func TestPythonDocumentationExamplesAreReview(t *testing.T) {
	docsOnly := "#!/usr/bin/python\n" +
		"DOCUMENTATION = r'''\nmodule: device_user\noptions:\n  password:\n    description: Login password.\n'''\n" +
		"EXAMPLES = r'''\n- name: Create a user\n  vendor.device.user:\n    host: device.example\n    username: admin\n    password: SomeSecretPassword\n'''\n" +
		"def main():\n    \"\"\"Connect with username: operator and password: Doc-Example-77.\"\"\"\n    pass\n"
	findings, candidates := harvestAt(t, "Scripts/modules/device_user.py", docsOnly)
	if n := confirmedCount(candidates); n > 0 {
		t.Errorf("documentation examples confirmed: %+v", candidates)
	}
	if len(actionableRules(findings)) > 0 {
		t.Errorf("documentation examples actionable: %v", actionableRules(findings))
	}
	kept := false
	for _, c := range candidates {
		if c.Value == "SomeSecretPassword" && c.Verification == credentialanalysis.Review {
			kept = true
		}
	}
	if !kept {
		t.Errorf("documentation example not kept as review material: %+v", candidates)
	}

	withCode := docsOnly + "\nUSERNAME = 'svc_backup'\nPASSWORD = 'Backup-Synth-Pass-41!'\nCONN = \"\"\"Server=db01.corp.example;User ID=svc_report;Password=Report-Synth-Pass-52;\"\"\"\n"
	findings, candidates = harvestAt(t, "Scripts/modules/device_user.py", withCode)
	got := confirmedPairs(candidates)
	if !got[harvestedPair{"svc_backup", "Backup-Synth-Pass-41!"}] {
		t.Errorf("credential in code lost next to documentation: %v", got)
	}
	connection := false
	for _, c := range candidates {
		if c.CredentialType == "connection_string" && c.Verification == credentialanalysis.Confirmed {
			connection = true
		}
	}
	if !connection {
		t.Errorf("connection string in a code string lost: %+v", candidates)
	}
	if len(actionableRules(findings)) == 0 {
		t.Errorf("credential in code is no longer actionable: %v", findingRuleSet(findings))
	}
}

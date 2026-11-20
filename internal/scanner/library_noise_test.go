package scanner

import (
	"testing"

	"snablr/internal/credentialanalysis"
)

func confirmedCount(candidates []credentialanalysis.Candidate) int {
	n := 0
	for _, c := range candidates {
		if c.Verification == credentialanalysis.Confirmed {
			n++
		}
	}
	return n
}

// Code that passes credentials around through variables, parameters and
// types names no account and no secret.
func TestCodeReferencesAreNotCredentials(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"module parameters", "Scripts/db_user.py", "user = module.params['login_user']\npassword = module.params['login_password']\n"},
		{"type annotations", "Scripts/client.py", "def connect(\n    username: str,\n    password: str,\n):\n    pass\n"},
		{"PowerShell typed defaults", "Modules/Join/Join.psm1", "[System.String] $Credential.UserName = [System.String] $null\n$UnjoinCredential = [System.String] $null\n"},
		{"call arguments", "Scripts/db.py", "conn = connect(host=self.host, user=self.user, password=self.password, database=self.database)\n"},
	} {
		findings, candidates := harvestAt(t, tc.path, tc.content)
		if n := confirmedCount(candidates); n > 0 {
			t.Errorf("%s: %d confirmed credentials: %+v", tc.name, n, candidates)
		}
		if len(actionableRules(findings)) > 0 {
			t.Errorf("%s: actionable findings %v", tc.name, actionableRules(findings))
		}
	}
	// A literal pair in the same kind of file stays a credential.
	findings, candidates := harvestAt(t, "Scripts/backup.py", "username = 'svc_backup'\npassword = 'Backup-Synth-Pass-41!'\n")
	if confirmedCount(candidates) == 0 || len(actionableRules(findings)) == 0 {
		t.Errorf("literal credential in a script lost: candidates=%+v findings=%v", candidates, findingRuleSet(findings))
	}
}

// Installed third-party library code (site-packages, node_modules, the
// Python standard library) holds documentation examples and test fixtures:
// review material, never confirmed or actionable.
func TestThirdPartyLibraryCodeIsReviewOnly(t *testing.T) {
	docs := "EXAMPLES = r'''\n- name: Create a user\n  vendor.device.user:\n    host: device.example\n    username: admin\n    password: SomeSecretPassword\n'''\nusername = 'admin'\npassword = 'SomeSecretPassword'\n"
	for _, path := range []string{
		"usr/lib/python3.12/site-packages/vendor/device/plugins/modules/user.py",
		"Tools/Python311/Lib/site-packages/vendor/device/user.py",
		"web/app/node_modules/vendor-client/README.md",
	} {
		findings, candidates := harvestAt(t, path, docs)
		if n := confirmedCount(candidates); n > 0 {
			t.Errorf("%s: %d confirmed credentials", path, n)
		}
		if len(actionableRules(findings)) > 0 {
			t.Errorf("%s: actionable findings %v", path, actionableRules(findings))
		}
	}
	keyFindings, keyCandidates := harvestAt(t, "usr/lib/python3.12/site-packages/vendorlib/tests/server.key", openSSHKey(t, ""))
	if confirmedCount(keyCandidates) > 0 || len(actionableRules(keyFindings)) > 0 {
		t.Errorf("library test key is confirmed or actionable: %v", actionableRules(keyFindings))
	}
	// A memory dump is directly exploitable wherever it lies.
	if got := outcomeAt(t, newNoiseEngine(t), "usr/lib/python3.12/site-packages/vendorlib/lsass.dmp", "MDMP"); !got.actionable["filename.memory_dump_artifacts"] {
		t.Errorf("memory dump in a library folder is not actionable: %v", got.rules)
	}
	// The same documentation outside library code keeps its findings.
	if findings, _ := harvestAt(t, "Scripts/device_user.py", docs); len(actionableRules(findings)) == 0 {
		t.Error("credentials outside library code are no longer actionable")
	}
}

// A DPAPI-protected value is never confirmed as a plaintext password.
func TestDPAPIBlobIsNotPlaintext(t *testing.T) {
	content := `<Settings><Username>CORP\svc_sql</Username><Password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAsyntheticBlob0123456789</Password></Settings>`
	_, candidates := harvestAt(t, "Setup/Datastore/ProductSettings.xml", content)
	for _, c := range candidates {
		if c.Verification == credentialanalysis.Confirmed {
			t.Errorf("DPAPI blob confirmed: %+v", c)
		}
	}
	found := false
	for _, c := range candidates {
		if c.Encrypted {
			found = true
		}
	}
	if !found {
		t.Errorf("DPAPI blob not kept as encrypted review material: %+v", candidates)
	}
}

package scanner

import (
	"path"
	"testing"
)

func evaluateAt(t *testing.T, engine *Engine, filePath, content string) []Finding {
	t.Helper()
	name := path.Base(filePath)
	return engine.Evaluate(FileMetadata{FilePath: filePath, Name: name, Extension: path.Ext(name), Size: int64(len(content))}, []byte(content)).Findings
}

func actionableRules(findings []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.Actionable {
			out[f.RuleID] = true
		}
	}
	return out
}

// Files that ship with Windows produce no findings on an admin share, while
// secret stores and real deployment files around them still do.
func TestWindowsComponentFoldersAreQuiet(t *testing.T) {
	engine := newNoiseEngine(t)
	for _, quiet := range []struct{ path, content string }{
		{"Windows/WinSxS/amd64_microsoft-windows-winrm_31bf/winrm.ini", "USERNAME = \"USERNAME\"\nPASSWORD = \"PASSWORD\"\n"},
		{"Windows/servicing/LCU/Package_for_RollupFix/amd64_tsportal/r/aspnetdb_log.ldf", "binary"},
		{"Windows/Microsoft.NET/Framework64/v4.0.30319/Config/web.config", "<configuration><connectionStrings><add name=\"x\" connectionString=\"Server=.;User ID=sa;Password=SampleOnly1\"/></connectionStrings></configuration>"},
		{"Users/alice/AppData/Local/Microsoft/Windows/Explorer/iconcache_16.db", "binary"},
		{"Windows/System32/MS-User.LDF", "dn: CN=User,CN=Schema\nchangetype: ntdsSchemaModify\n"},
	} {
		if findings := evaluateAt(t, engine, quiet.path, quiet.content); len(findings) > 0 {
			t.Errorf("%s produced findings: %v", quiet.path, findingRuleSet(findings))
		}
	}
	for _, reported := range []struct{ path, rule string }{
		{"Windows/WinSxS/amd64_microsoft-windows-d..rvices-domain-files/ntds.dit", "filename.secret_store_artifacts"},
		{"Windows/System32/config/SAM", "filename.secret_store_artifacts"},
		{"Data/payroll_log.ldf", "dbinspect.artifact.mssql_ldf"},
	} {
		if !findingRuleSet(evaluateAt(t, engine, reported.path, "binary"))[reported.rule] {
			t.Errorf("%s no longer reported as %s", reported.path, reported.rule)
		}
	}
	scrubbed := `<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup"><AutoLogon><Enabled>true</Enabled><Username>deployadmin</Username><Password>*SENSITIVE*DATA*DELETED*</Password></AutoLogon><UserAccounts><AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword></UserAccounts></component></settings></unattend>`
	if rules := actionableRules(evaluateAt(t, engine, "Windows/Panther/unattend.xml", scrubbed)); len(rules) > 0 {
		t.Errorf("unattend file scrubbed by Windows setup is actionable: %v", rules)
	}
	unattend := `<unattend><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup"><AutoLogon><Enabled>true</Enabled><Username>kioskadmin</Username><Password><Value>Kiosk-Logon-2026!</Value><PlainText>true</PlainText></Password></AutoLogon></component></settings></unattend>`
	real := actionableRules(evaluateAt(t, engine, "Windows/Panther/unattend.xml", unattend))
	if !real[ConfirmedCredentialRuleID] || !real["windowsinspect.unattend.structured"] {
		t.Errorf("a real unattend password in Panther is no longer actionable: %v", real)
	}
}

// Text that only names an account, or mentions a password in a sentence, is
// not a credential; the real pairs next to them still are.
func TestAccountHeadersAndProseAreNotCredentials(t *testing.T) {
	engine := newNoiseEngine(t)
	transcript := "**********************\nWindows PowerShell transcript start\nUsername: BUILD-SRV01\\deployadmin\nRunAs User: BUILD-SRV01\\deployadmin\nMachine: BUILD-SRV01\n"
	if findingRuleSet(evaluateAt(t, engine, "logs/setup-transcript.txt", transcript))["content.note_style_credential_pair_indicators"] {
		t.Error("transcript header reported as a credential pair")
	}
	note := "VPN access\nUsername: CORP\\svc_vpn\nPassword: Winter-Vpn-2026!\n"
	if !findingRuleSet(evaluateAt(t, engine, "notes/vpn.txt", note))["content.note_style_credential_pair_indicators"] {
		t.Error("a real account and password note is no longer reported")
	}
	readme := "3. Create an Active Directory service account and keep the account password available.\n"
	if findingRuleSet(evaluateAt(t, engine, "setup/readme_crp.txt", readme))["content.password_note_value_indicators"] {
		t.Error("readme prose reported as a password note")
	}
	if !findingRuleSet(evaluateAt(t, engine, "notes/router.txt", "router password Summer-Router-26\n"))["content.password_note_value_indicators"] {
		t.Error("a real password note is no longer reported")
	}
	script := "$ndesServiceAccountPassword = $null\n"
	if actionableRules(evaluateAt(t, engine, "setup/Test-NDES-CRP-Prereqs.ps1", script))["content.password_assignment_indicators"] {
		t.Error("a $null assignment is actionable")
	}
	if !actionableRules(evaluateAt(t, engine, "scripts/deploy.ps1", "$password = \"Deploy-Real-2026!\"\n"))["content.password_assignment_indicators"] {
		t.Error("a real password assignment is no longer actionable")
	}
}

func TestCloudAcronymsMatchWholeNameParts(t *testing.T) {
	engine := newNoiseEngine(t)
	if findingRuleSet(evaluateAt(t, engine, "DataLib/amd64/ngcpopkeysrv_dll-repl.man.INI", "[x]\n"))["filename.cloud_configuration_names"] {
		t.Error("\"gcp\" matched inside an unrelated file name")
	}
	for _, name := range []string{"keys/gcp-key.json", "keys/aws-creds.json", "deploy/docker-compose.yml"} {
		if !findingRuleSet(evaluateAt(t, engine, name, "{}"))["filename.cloud_configuration_names"] {
			t.Errorf("%s no longer matches the cloud configuration names", name)
		}
	}
}

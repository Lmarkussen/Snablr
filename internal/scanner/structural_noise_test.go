package scanner

import "testing"

// Windows setup scrubs the passwords of the answer file it keeps under
// Panther. The password field names alone are no credential: the file stays
// reported through its name, but is not actionable.
func TestScrubbedUnattendIsNotActionable(t *testing.T) {
	scrubbed := `<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>builder</Username>
        <Password>*SENSITIVE*DATA*DELETED*</Password>
      </AutoLogon>
      <UserAccounts>
        <AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password>*SENSITIVE*DATA*DELETED*</Password>
            <Name>builder</Name>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
    </component>
  </settings>
</unattend>
`
	findings, _ := harvestAt(t, "Windows/Panther/unattend.xml", scrubbed)
	if len(findings) == 0 {
		t.Fatal("scrubbed unattend is no longer reported")
	}
	if rules := actionableRules(findings); len(rules) > 0 {
		t.Errorf("scrubbed unattend is actionable: %v", rules)
	}
	if findingRuleSet(findings)["content.remote_access_saved_password"] {
		t.Error("unattend <Password> reported as a remote-access client store")
	}

	plain := `<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup"><UserAccounts><AdministratorPassword><Value>Harbor-Unatt-2026</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts></component></settings></unattend>`
	findings, _ = harvestAt(t, "Windows/Panther/unattend.xml", plain)
	if len(actionableRules(findings)) == 0 {
		t.Errorf("unattend with a plaintext password is not actionable: %v", findingRuleSet(findings))
	}
	if findingRuleSet(findings)["content.remote_access_saved_password"] {
		t.Error("unattend password reported as a remote-access client store")
	}
}

// RDCMan stores its saved password in a lowercase <password> element; that
// stays a remote-access client store finding.
func TestRDCManPasswordStillMatches(t *testing.T) {
	rdg := `<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.7" schemaVersion="3">
  <file>
    <server><properties><name>app01.corp.example</name></properties>
      <logonCredentials inherit="None"><profileName scope="Local">Custom</profileName><userName>ops</userName><password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAc3ludGhldGljLWJsb2I=</password><domain>CORP</domain></logonCredentials>
    </server>
  </file>
</RDCMan>
`
	findings, _ := harvestAt(t, "Users/ops/Documents/servers.rdg", rdg)
	if !findingRuleSet(findings)["content.remote_access_saved_password"] {
		t.Errorf("RDCMan saved password not reported: %v", findingRuleSet(findings))
	}
}

// A Group Policy Preferences document is actionable for a cpassword that
// decrypts. One whose cpassword does not decrypt is still reported, but as
// review material.
func TestGPPWithoutDecryptablePasswordIsNotActionable(t *testing.T) {
	groups := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalSupport" image="2" changed="2026-01-01 00:00:00" uid="{00000000-0000-4000-8000-000000000001}"><Properties action="U" newName="" fullName="" description="" cpassword="NOT-A-VALID-GPP-CIPHERTEXT" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="LocalSupport"/></User></Groups>
`
	path := "SYSVOL/corp.example/Policies/{00000000-0000-4000-8000-000000000002}/Machine/Preferences/Groups/Groups.xml"
	findings, _ := harvestAt(t, path, groups)
	if !findingRuleSet(findings)["windowsinspect.gpp.groups"] {
		t.Fatalf("GPP document no longer reported: %v", findingRuleSet(findings))
	}
	if rules := actionableRules(findings); len(rules) > 0 {
		t.Errorf("GPP document without a decryptable password is actionable: %v", rules)
	}
}

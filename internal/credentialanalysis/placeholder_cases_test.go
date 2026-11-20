package credentialanalysis

import "testing"

func TestPlaceholderCasesFoundOnRealSystems(t *testing.T) {
	for _, value := range []string{
		"*SENSITIVE*DATA*DELETED*",
		`""PASSWORD""`, `"USERNAME"`, "PASSWORD", "USERNAME",
		"$clearText", "$Value.UserName", "$Password.Password))", "$null", "$env:APP_PASSWORD",
		"AutoGenerate", "AutoGenerate,IsolateApps",
	} {
		if !IsPlaceholderValue(value) {
			t.Errorf("%q not recognised as a placeholder", value)
		}
	}
	for _, value := range []string{
		"password", "Password", "Passw0rd", "$ecret2026!", "$Pa55word", "AutoGenerate1", "autogeneratepass", "SENSITIVE-DATA-2026",
	} {
		if IsPlaceholderValue(value) {
			t.Errorf("real-looking value %q treated as a placeholder", value)
		}
	}
	for _, identity := range []string{"USERNAME", "username", `"user"`, "Login"} {
		if !IsPlaceholderIdentity(identity) {
			t.Errorf("identity %q not recognised as a placeholder", identity)
		}
	}
	for _, identity := range []string{"svc_backup", "deployadmin", "username1", `CORP\user`} {
		if IsPlaceholderIdentity(identity) {
			t.Errorf("real identity %q treated as a placeholder", identity)
		}
	}
}

// Windows setup scrubs unattend passwords after use; the scrubbed file holds
// no credential.
func TestHarvestIgnoresScrubbedUnattendPasswords(t *testing.T) {
	content := `<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup">
<AutoLogon><Enabled>true</Enabled><Username>deployadmin</Username><Password>*SENSITIVE*DATA*DELETED*</Password></AutoLogon>
<UserAccounts><AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>
<LocalAccounts><LocalAccount><Password>*SENSITIVE*DATA*DELETED*</Password><Name>deployadmin</Name></LocalAccount></LocalAccounts></UserAccounts>
</component></settings></unattend>`
	if candidates := Harvest(HarvestInput{Content: []byte(content), Path: "Windows/Panther/unattend.xml"}); len(candidates) != 0 {
		t.Fatalf("scrubbed unattend produced %d candidates: %+v", len(candidates), candidates)
	}
}

// Usage text in WinRM scripts ("username : password") names no account.
func TestHarvestIgnoresFieldNameAccounts(t *testing.T) {
	content := "  Example: winrm set winrm/config -r:HOST -u:username -p:password\n  username : password\n"
	for _, candidate := range Harvest(HarvestInput{Content: []byte(content), Path: "Windows/System32/winrm.vbs"}) {
		if candidate.Verification == Confirmed {
			t.Fatalf("usage text confirmed a credential: %+v", candidate)
		}
	}
}

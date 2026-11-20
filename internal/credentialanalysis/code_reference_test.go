package credentialanalysis

import "testing"

func TestCodeReferencesAreRecognised(t *testing.T) {
	for _, value := range []string{
		"module.params['login_user']",
		`module.params[\"login_password\"]`,
		"self.username",
		"module.params[",
		"self.get_password(",
		"self.module.params['password'],",
		"config.db_password",
		"str,",
		"user;",
		"password;",
		"[user;]",
		"[password]",
		"[System.String] $null",
		"[string]$Password",
		"$tokens[$i]",
		"idrac_password",
		"dummy_password",
		"api_pwd",
		"string",
		"str",
		`"",`,
		`\"\",`,
		"0x00000010,",
	} {
		if !IsCodeReference(value) {
			t.Errorf("%q not recognised as a code reference", value)
		}
	}
	for _, value := range []string{
		"Summer2026!",
		"P@ss;w0rd",
		"Winter-Deploy-2026",
		`CORP\svc_sql`,
		"john.smith",
		"app.service",
		"svc_backup",
		"Secret_Password1",
		"data.base",
		"admin",
		"correct horse",
		"Sql-Svc-Pass-2026;",
		"Pa55word[",
		"1234,",
	} {
		if IsCodeReference(value) {
			t.Errorf("%q treated as a code reference", value)
		}
	}
}

func TestThirdPartyLibraryPaths(t *testing.T) {
	for _, path := range []string{
		"usr/lib/python3.12/site-packages/pkg/module.py",
		"opt/app/venv/lib/python3.11/site-packages/pkg/docs.md",
		"usr/lib/python3/dist-packages/pkg/__init__.py",
		"usr/lib/python3.14/email/utils.py",
		"Tools/Python311/Lib/smtplib.py",
		`Program Files\Python312\Lib\site-packages\requests\auth.py`,
		"web/app/node_modules/pg/lib/client.js",
		"Archive/env.zip!lib/python3.10/site-packages/x/conf.py",
	} {
		if !ThirdPartyLibraryPath(path) {
			t.Errorf("%s not recognised as library code", path)
		}
	}
	for _, path := range []string{
		"Scripts/deploy.py",
		"IT/Python/backup.py",
		"Projects/python3/notes.txt",
		"Vendor/Contracts/credentials.txt",
		"lib/settings.py",
	} {
		if ThirdPartyLibraryPath(path) {
			t.Errorf("%s treated as library code", path)
		}
	}
}

func TestDPAPIBlobsAreRecognised(t *testing.T) {
	for _, value := range []string{
		"AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAsyntheticBlob0123",
		"01000000D08C9DDF0115D1118C7A00C04FC297EB01000000",
		"0601000001000000d08c9ddf0115d1118c7a00c04fc297eb0100",
	} {
		if !IsDPAPIBlob(value) {
			t.Errorf("%q not recognised as a DPAPI blob", value)
		}
	}
	if IsDPAPIBlob("AQAAANCMnotAblob") || IsDPAPIBlob("Summer2026!") {
		t.Error("ordinary value treated as a DPAPI blob")
	}
}

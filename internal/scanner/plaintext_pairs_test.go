package scanner

import (
	"strings"
	"testing"

	"snablr/internal/credentialanalysis"
)

type harvestedPair struct{ identity, value string }

func harvestAt(t *testing.T, path, content string) ([]Finding, []credentialanalysis.Candidate) {
	t.Helper()
	engine := newNoiseEngine(t)
	recorder := &recordingCandidateSink{}
	engine.SetCredentialCandidateSink(recorder)
	findings := evaluateAt(t, engine, path, content)
	return findings, recorder.candidates
}

func confirmedPairs(candidates []credentialanalysis.Candidate) map[harvestedPair]bool {
	out := map[harvestedPair]bool{}
	for _, c := range candidates {
		if c.Verification == credentialanalysis.Confirmed {
			out[harvestedPair{c.Identity, c.Value}] = true
		}
	}
	return out
}

// Deployment files and admin command lines that state an account and its
// password in product-specific or positional form are confirmed credentials
// with an actionable finding.
func TestDeploymentAndCommandPairsAreConfirmed(t *testing.T) {
	cases := []struct {
		name, path, content string
		want                []harvestedPair
	}{
		{
			"SQL Server setup configuration file",
			"setup/sqlserver/ConfigurationFile.ini",
			";SQL Server Configuration File\n[OPTIONS]\nACTION=\"Install\"\nAGTSVCACCOUNT=\"NT AUTHORITY\\NETWORK SERVICE\"\nSQLSVCACCOUNT=\"corp.example\\svc-sql\"\nSQLSVCPASSWORD=\"Sql-Svc-Pass-2026\"\nSQLTELSVCACCT=\"corp.example\\svc-sqltel\"\nSQLTELSVCPASSWORD=\"Sql-Tel-Pass-2026\"\nSAPWD=\"Sa-Pass-Synthetic-1!\"\nTCPENABLED=\"1\"\n",
			[]harvestedPair{{"sa", "Sa-Pass-Synthetic-1!"}, {`corp.example\svc-sql`, "Sql-Svc-Pass-2026"}, {`corp.example\svc-sqltel`, "Sql-Tel-Pass-2026"}},
		},
		{
			"MDT CustomSettings.ini",
			"DeploymentShare/Control/CustomSettings.ini",
			"[Settings]\nPriority=Default\n\n[Default]\nOSInstall=Y\nAdminPassword=Local-Admin-Synth-84\nJoinDomain=corp.example\nDomainAdmin=svc_joiner\nDomainAdminDomain=CORP\nDomainAdminPassword=Join-Synth-Acct-2716\n",
			[]harvestedPair{{"svc_joiner", "Join-Synth-Acct-2716"}, {"Administrator", "Local-Admin-Synth-84"}},
		},
		{
			"net use with password before /user",
			"Scripts/Startup/map-drive.cmd",
			"@echo off\nnet use Z: \\\\fs01\\deploy Map-Drive-Synth-2026 /user:CORP\\svc_map /persistent:no\n",
			[]harvestedPair{{`CORP\svc_map`, "Map-Drive-Synth-2026"}},
		},
		{
			"net use with password after /user",
			"Scripts/Startup/map-share.bat",
			"NET USE \\\\fs02\\builds /user:CORP\\svc_build Build-Share-Synth-11\n",
			[]harvestedPair{{`CORP\svc_build`, "Build-Share-Synth-11"}},
		},
		{
			"PowerShell history",
			"Users/admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
			"Get-ADUser -Filter * | Measure-Object\nInvoke-Sqlcmd -ServerInstance db01.corp.example -Username sa -Password 'Sa-Hist-Synth#4417' -Query \"SELECT 1\"\ncmdkey /add:rdgw01.corp.example /user:CORP\\svc_rdpgw /pass:Cmdkey-Synth-7720\nnet user svc_staging Staging-Synth-Acct-63! /add /domain\n$cred = New-Object System.Management.Automation.PSCredential('CORP\\svc_archive', (ConvertTo-SecureString 'Arch-Synth!2031-Kq2' -AsPlainText -Force))\n",
			[]harvestedPair{{"sa", "Sa-Hist-Synth#4417"}, {`CORP\svc_rdpgw`, "Cmdkey-Synth-7720"}, {"svc_staging", "Staging-Synth-Acct-63!"}, {`CORP\svc_archive`, "Arch-Synth!2031-Kq2"}},
		},
		{
			"PSCredential from a secure-string variable",
			"Scripts/backup.ps1",
			"$secure = ConvertTo-SecureString -String \"Var-Synth-Pass-42\" -AsPlainText -Force\n$cred = [pscredential]::new('CORP\\svc_var', $secure)\n",
			[]harvestedPair{{`CORP\svc_var`, "Var-Synth-Pass-42"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, candidates := harvestAt(t, tc.path, tc.content)
			got := confirmedPairs(candidates)
			for _, want := range tc.want {
				if !got[want] {
					t.Errorf("missing confirmed %s / %s; confirmed=%v", want.identity, want.value, got)
				}
			}
			if !actionableRules(findings)[ConfirmedCredentialRuleID] {
				t.Errorf("no actionable confirmed-credential finding: %v", findingRuleSet(findings))
			}
		})
	}
}

// Prompts, variables, built-in service accounts, deletions and listings are
// not credentials, and admin_password outside MDT rules keeps its generic
// handling.
func TestDeploymentAndCommandNegativeControls(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"net use prompts and templates", "Scripts/a.cmd", "net use Z: \\\\fs01\\deploy * /user:CORP\\svc_map\nnet use Y: \\\\fs01\\data /user:CORP\\svc_map\nnet use %DRV% \\\\fs01\\x %PASS% /user:%USER%\nnet user svc_map /domain\nnet user %USERNAME% *\nnet use \\\\fs01\\ipc$ /delete\n"},
		{"credentials without plaintext", "Scripts/b.ps1", "$c = Get-Credential\n$x = New-Object PSCredential('CORP\\svc', $c.Password)\n$p = Read-Host -AsSecureString\n$y = New-Object PSCredential('CORP\\svc', $p)\n"},
		{"SQL setup without passwords", "setup/ConfigurationFile.ini", "[OPTIONS]\nSQLSVCACCOUNT=\"NT Service\\MSSQLSERVER\"\nAGTSVCACCOUNT=\"NT AUTHORITY\\NETWORK SERVICE\"\nSAPWD=\"\"\nSECURITYMODE=\"SQL\"\n"},
	} {
		if _, candidates := harvestAt(t, tc.path, tc.content); len(candidates) > 0 {
			t.Errorf("%s: harvested %+v", tc.name, candidates)
		}
	}
	_, candidates := harvestAt(t, "app/settings.ini", "[database]\nadmin_password = Db-Synth-Admin-8\n")
	for _, c := range candidates {
		if c.Identity == "Administrator" || c.Verification == credentialanalysis.Confirmed {
			t.Errorf("admin_password outside MDT rules was paired: %+v", c)
		}
	}
	if pairs := confirmedPairs(func() []credentialanalysis.Candidate {
		_, c := harvestAt(t, "grafana/grafana.ini", "[security]\nadmin_user = admin\nadmin_password = Grafana-Synth-Admin-7\n")
		return c
	}()); !pairs[harvestedPair{"admin", "Grafana-Synth-Admin-7"}] {
		t.Errorf("generic admin_user/admin_password pair is no longer confirmed: %v", pairs)
	}
}

// Items of a "secrets:" list carry no account: they are review material
// and surface as a review finding, also when the YAML is inside a text file.
func TestYAMLSecretListsAreReviewMaterial(t *testing.T) {
	content := "accounts:\n  - name: svc_beta\n  - name: other-9\nsecrets:\n  - value: Beta-Synth-Secret-2\n  - value: unrelated-secret\n"
	for _, path := range []string{"Deploy/services.yaml", "nested/ambiguous.txt"} {
		findings, candidates := harvestAt(t, path, content)
		var review []string
		for _, c := range candidates {
			if c.Verification == credentialanalysis.Confirmed {
				t.Errorf("%s: secret list item confirmed: %+v", path, c)
			}
			review = append(review, c.Value)
		}
		if !strings.Contains(strings.Join(review, ","), "Beta-Synth-Secret-2") {
			t.Errorf("%s: secret list item not harvested: %v", path, review)
		}
		if len(actionableRules(findings)) > 0 {
			t.Errorf("%s: actionable findings %v", path, actionableRules(findings))
		}
	}
	if findings, _ := harvestAt(t, "nested/ambiguous.txt", content); !findingRuleSet(findings)[ReviewCredentialRuleID] {
		t.Error("secret list in a text file raised no review finding")
	}
}

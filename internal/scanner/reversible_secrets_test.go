package scanner

import (
	"testing"

	"snablr/internal/credentialanalysis"
)

// Passwords protected only by a public key or a fixed obfuscation (GPP
// cpassword, unattend PlainText=false, WinSCP, FileZilla base64, mRemoteNG
// default key) are decoded to confirmed credentials with an actionable
// finding. The ciphertexts were made from synthetic plaintexts with the
// encoders in credentialanalysis/decode_test.go.
func TestReversibleSecretsAreDecodedAndConfirmed(t *testing.T) {
	cases := []struct {
		name, path, content string
		want                harvestedPair
	}{
		{
			"GPP drive map",
			"Policies/{6A1B2C3D-0000-4000-8000-000000000001}/User/Preferences/Drives/Drives.xml",
			`<?xml version="1.0" encoding="utf-8"?><Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"><Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:" status="S:" image="2"><Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="CORP\svc_files" cpassword="NN8Hx8CgT4wmEEAewLPJLFtcO72FcpGJw8KTgIRrYIyVF6RbFaLf56FCleZ7sNtf" path="\\fs01\shared" label="Shared" persistent="1" useLetter="1" letter="S"/></Drive></Drives>`,
			harvestedPair{`CORP\svc_files`, "Gpp-Synth-Drive-11"},
		},
		{
			"unattend AdministratorPassword",
			"Windows/Panther/unattend.xml",
			`<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup"><UserAccounts><AdministratorPassword><Value>QQBkAG0AaQBuAC0AUwB5AG4AdABoAC0AVQBuAGEAdAB0AC0AMQAyAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAUABhAHMAcwB3AG8AcgBkAA==</Value><PlainText>false</PlainText></AdministratorPassword></UserAccounts></component></settings></unattend>`,
			harvestedPair{"Administrator", "Admin-Synth-Unatt-12"},
		},
		{
			"WinSCP session",
			"Users/deploy/AppData/Roaming/WinSCP.ini",
			"[Sessions\\svc_sftp@files.corp.example]\nHostName=files.corp.example\nUserName=svc_sftp\nPassword=A35C705E6C6D2F2A3F032F3A282C3A3530392F723F332E2C7239243D312C30390F3A282C710F25322834710C3D2F2F716D6F\n",
			harvestedPair{"svc_sftp", "Sftp-Synth-Pass-13"},
		},
		{
			"FileZilla site manager",
			"Users/deploy/AppData/Roaming/FileZilla/sitemanager.xml",
			`<?xml version="1.0" encoding="UTF-8"?><FileZilla3><Servers><Server><Host>ftp.corp.example</Host><Port>21</Port><Protocol>0</Protocol><User>ftp_release</User><Pass encoding="base64">RnRwLVN5bnRoLVBhc3MtMTQ=</Pass></Server></Servers></FileZilla3>`,
			harvestedPair{"ftp_release", "Ftp-Synth-Pass-14"},
		},
		{
			"mRemoteNG default key",
			"Users/deploy/AppData/Roaming/mRemoteNG/confCons.xml",
			`<?xml version="1.0" encoding="utf-8"?><mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" ConfVersion="2.6"><Node Name="dc01" Type="Connection" Username="rdp_ops" Domain="CORP" Password="ERERERERERERERERERERESIiIiIiIiIiIiIiIiIiIiJu9JdsMEaoZksVHOWF5hN9kdOaBeJaXicdlOuPWrtFdO4=" Hostname="dc01.corp.example" Protocol="RDP" /></mrng:Connections>`,
			harvestedPair{`CORP\rdp_ops`, "Rdp-Synth-Pass-15"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, candidates := harvestAt(t, tc.path, tc.content)
			if !confirmedPairs(candidates)[tc.want] {
				t.Errorf("missing confirmed %s / %s; confirmed=%v", tc.want.identity, tc.want.value, confirmedPairs(candidates))
			}
			if !actionableIncludingMerged(findings)[ConfirmedCredentialRuleID] {
				t.Errorf("confirmed credential is not part of an actionable finding: %v", findingRuleSet(findings))
			}
		})
	}
}

// actionableIncludingMerged returns every rule that is part of an
// actionable finding, including rules merged into another primary rule.
func actionableIncludingMerged(findings []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if !f.Actionable {
			continue
		}
		for _, id := range append([]string{f.RuleID}, f.MatchedRuleIDs...) {
			out[id] = true
		}
	}
	return out
}

// Values protected by the user's own master password, or that do not
// decode, stay review material and are never confirmed.
func TestUndecodableStoredPasswordsStayReview(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"mRemoteNG custom master password", "Users/deploy/AppData/Roaming/mRemoteNG/confCons.xml", `<mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false"><Node Name="dc01" Username="rdp_ops" Domain="CORP" Password="ERERERERERERERERERERESIiIiIiIiIiIiIiIiIiIiJeqjXPe6hXs6KysyviQL79z5GDUQDAq9q1MorNEWcjId8=" Hostname="dc01.corp.example" /></mrng:Connections>`},
		{"FileZilla master password", "Users/deploy/AppData/Roaming/FileZilla/sitemanager.xml", `<FileZilla3><Servers><Server><Host>ftp.corp.example</Host><User>ftp_release</User><Pass encoding="crypt" pubkey="AAAA">BBBBCCCC</Pass></Server></Servers></FileZilla3>`},
		{"WinSCP value that does not decode", "Users/deploy/AppData/Roaming/WinSCP.ini", "[Sessions\\svc@files.corp.example]\nHostName=files.corp.example\nUserName=svc_synthetic\nPassword=A35C455A1D6E6D6E6F6F6E6D3B323D3B2E7A6F6C696D\n"},
		{"GPP value that does not decrypt", "Policies/{6A1B2C3D-0000-4000-8000-000000000002}/Machine/Preferences/Groups/Groups.xml", `<Groups><User name="svc_bad"><Properties action="U" cpassword="AQAAAINVALID-SYNTHETIC-CPASSWORD-0000" userName="svc_bad"/></User></Groups>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, candidates := harvestAt(t, tc.path, tc.content)
			for _, c := range candidates {
				if c.Verification == credentialanalysis.Confirmed {
					t.Errorf("confirmed: %+v", c)
				}
			}
			for _, f := range findings {
				for _, id := range append([]string{f.RuleID}, f.MatchedRuleIDs...) {
					if id == ConfirmedCredentialRuleID {
						t.Errorf("confirmed-credential finding raised in %s", f.RuleID)
					}
				}
			}
		})
	}
}

package scanner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fileOutcome summarises every finding raised for one file.
type fileOutcome struct {
	rules      map[string]bool
	actionable map[string]bool
}

func outcomeAt(t *testing.T, engine *Engine, filePath, content string) fileOutcome {
	t.Helper()
	findings := evaluateAt(t, engine, filePath, content)
	out := fileOutcome{rules: map[string]bool{}, actionable: map[string]bool{}}
	for _, f := range findings {
		for _, id := range append([]string{f.RuleID}, f.MatchedRuleIDs...) {
			out.rules[id] = true
			if f.Actionable {
				out.actionable[id] = true
			}
		}
	}
	return out
}

func openSSHKey(t *testing.T, passphrase string) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	var (
		block *pem.Block
		err   error
	)
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, "deploy@build")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "deploy@build", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func encryptedPEMKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1019 legacy encrypted PEM is what real shares hold.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte("synthetic-passphrase"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// Protected secret material (passphrase-protected keys, DPAPI blobs,
// certificate stores, credential stores) needs decryption or cracking before
// use, so it is reported for review and never as actionable. The same
// formats without protection stay actionable.
func TestProtectedSecretMaterialIsReviewNotActionable(t *testing.T) {
	engine := newNoiseEngine(t)
	review := []struct{ path, content, rule string }{
		{"Users/deploy/.ssh/id_ed25519_build", openSSHKey(t, "synthetic-passphrase"), "keyinspect.content.private_key_header"},
		{"Users/deploy/.ssh/id_ed25519", openSSHKey(t, "synthetic-passphrase"), "keyinspect.content.private_key_header"},
		{"IT/Keys/legacy-backup.pem", encryptedPEMKey(t), "keyinspect.content.private_key_header"},
		{"Users/deploy/Documents/RDP/db-admin.rdp", "full address:s:db01.corp.example\nusername:s:CORP\\deployadmin\npassword 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB0100000052A9E191EA75A948B359790578C9371A\n", "content.remote_access_saved_password"},
		{"IT/Admin/servers.rdg", `<RDCMan><file><server><properties><name>srv01.corp.example</name></properties><logonCredentials inherit="None"><userName>deployadmin</userName><password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAsyntheticBlob0123</password><domain>CORP</domain></logonCredentials></server></file></RDCMan>`, "content.remote_access_saved_password"},
		{"IT/Certs/corp-admin.pfx", "binary", "extension.key_and_certificate_extensions"},
		{"IT/Certs/branch-admin.p12", "binary", "extension.key_and_certificate_extensions"},
		{"Users/deploy/AppData/Roaming/Microsoft/Credentials/0A1B2C3D4E5F60718293A4B5C6D7E8F9", "binary", "wincredinspect.path.credentials"},
		{"Users/deploy/AppData/Local/Microsoft/Vault/5A6B7C8D-0000-4000-8000-123456789ABC/Policy.vpol", "binary", "wincredinspect.path.vault"},
		{"Users/deploy/AppData/Roaming/Microsoft/Protect/S-1-5-21-1-2-3-1104/00000000-1111-2222-3333-444444444444", "binary", "wincredinspect.path.protect"},
		{"IT/VPN/client.ovpn", "client\ndev tun\nremote vpn.corp.example 1194\nauth-user-pass\nca ca.crt\ncert client.crt\nkey client.key\n", "extension.client_auth_artifacts"},
		{"Apps/Oracle/network/admin/tnsnames.ora", "ORCL =\n  (DESCRIPTION =\n    (ADDRESS = (PROTOCOL = TCP)(HOST = db01.corp.example)(PORT = 1521))\n    (CONNECT_DATA = (SERVICE_NAME = orcl))\n  )\n", "dbinspect.artifact.oracle_tnsnames"},
	}
	for _, tc := range review {
		got := outcomeAt(t, engine, tc.path, tc.content)
		if !got.rules[tc.rule] {
			t.Errorf("%s is no longer reported as %s: %v", tc.path, tc.rule, got.rules)
		}
		if len(got.actionable) > 0 {
			t.Errorf("%s is actionable, want review only: %v", tc.path, got.actionable)
		}
	}

	actionable := []struct{ path, content, rule string }{
		{"Users/deploy/.ssh/id_ed25519", openSSHKey(t, ""), "keyinspect.content.private_key_header"},
		{"Users/deploy/OpenVPN/config/office-vpn.ovpn", "client\nremote vpn.corp.example 1194\n<key>\n" + openSSHKey(t, "") + "</key>\n", "keyinspect.content.private_key_header"},
		{"Users/deploy/AppData/Roaming/FileZilla/sitemanager.xml", `<FileZilla3><Servers><Server><Host>ftp.corp.example</Host><User>svc_ftp</User><Pass encoding="base64">U3ludGhldGljLUZ0cC0xIQ==</Pass></Server></Servers></FileZilla3>`, "content.remote_access_saved_password"},
		{"IT/Tools/mRemoteNG/confCons.xml", `<mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"><Node Name="dc01" Username="deployadmin" Domain="CORP" Password="R5SJ0nW0zv9mR4Y3XQf8rJ7nD3gH2kP9uL1qB6tE0wA=" Hostname="dc01.corp.example" /></mrng:Connections>`, "content.remote_access_saved_password"},
		{"Users/deploy/AppData/Roaming/WinSCP.ini", "[Sessions\\svc@files.corp.example]\nHostName=files.corp.example\nUserName=svc_files\nPassword=A35C455A1D6E6D6E6F6F6E6D3B323D3B2E7A6F6C696D\n", "content.remote_access_saved_password"},
	}
	for _, tc := range actionable {
		if got := outcomeAt(t, engine, tc.path, tc.content); !got.actionable[tc.rule] {
			t.Errorf("%s is no longer actionable as %s: rules=%v actionable=%v", tc.path, tc.rule, got.rules, got.actionable)
		}
	}
}

// Live registry hives, RegBack copies and template hives under WinSxS or the
// Application Guard container stay actionable by name (policy decision).
func TestWindowsHivesStayActionable(t *testing.T) {
	engine := newNoiseEngine(t)
	for _, tc := range []struct{ path, rule string }{
		{"Windows/System32/config/SAM", "filename.secret_store_artifacts"},
		{"Windows/System32/config/SYSTEM", "filename.windows_hive_artifacts"},
		{"Windows/System32/config/SECURITY", "filename.windows_hive_artifacts"},
		{"Windows/System32/config/RegBack/SAM", "filename.secret_store_artifacts"},
		{"Windows/System32/config/RegBack/SYSTEM", "filename.windows_hive_artifacts"},
		{"Windows/System32/config/RegBack/SECURITY", "filename.windows_hive_artifacts"},
		{"Windows/WinSxS/amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_10.0.17763.1_none/ntds.dit", "filename.secret_store_artifacts"},
		{"Windows/Containers/serviced/Files/Windows/System32/config/SAM", "filename.secret_store_artifacts"},
	} {
		if got := outcomeAt(t, engine, tc.path, "binary"); !got.actionable[tc.rule] {
			t.Errorf("%s is no longer actionable as %s: rules=%v actionable=%v", tc.path, tc.rule, got.rules, got.actionable)
		}
	}
}

package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/pkg/logx"
)

const mib = 1024 * 1024

// High-value artifacts that were previously skipped, dropped by the size gate
// or not recognised must be reported, with the expected actionability.
func TestHighValueArtifactCoverage(t *testing.T) {
	cases := []struct {
		path, content string
		size          int64
		rule          string
		actionable    bool
	}{
		{"Backups/Hyper-V/DC01.vhdx", "vhdxfile", 4096 * mib, "extension.virtual_disk_and_memory_images", true},
		{"Backups/VMs/fs01-flat.vmdk", "KDMV", 2048 * mib, "extension.virtual_disk_and_memory_images", true},
		{"VMs/fs01/fs01-Snapshot1.vmem", "", 4096 * mib, "extension.virtual_disk_and_memory_images", true},
		{"Users/Admin/Desktop/lsass.dmp", "MDMP", 80 * mib, "filename.memory_dump_artifacts", true},
		{"Users/Admin/tickets/administrator.kirbi", "\x76\x82\x05\x00", 0, "filename.kerberos_ticket_artifacts", true},
		{"tmp/krb5cc_1000", "\x05\x04\x00\x0c", 0, "filename.kerberos_ticket_artifacts", true},
		{"IT/Linux/http.keytab", "\x05\x02\x00\x00", 0, "filename.kerberos_ticket_artifacts", true},
		{"Mail/Archive/old-mail.pst", "!BDN", 500 * mib, "extension.mail_store_archives", false},
		{"ISO/boot-media.iso", "CD001", 400 * mib, "extension.optical_disk_images", false},
		{"Users/Bob/Desktop/nopass.rdp", "full address:s:jump.synthetic\nusername:s:svc_synthetic\n", 0, "filename.remote_access_client_configs", false},
		{"Users/Bob/Desktop/jump.rdp", "full address:s:jump.synthetic\npassword 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB01000000\n", 0, "content.remote_access_saved_password", true},
		{"Users/Bob/AppData/Roaming/FileZilla/sitemanager.xml", `<FileZilla3><Servers><Server><Host>ftp.synthetic</Host><User>svc_synthetic</User><Pass encoding="base64">U3ludGhldGljLUZ0cC0xIQ==</Pass></Server></Servers></FileZilla3>`, 0, "content.remote_access_saved_password", true},
		{"IT/VPN/wg0.conf", "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.200.0.2/32\n", 0, "content.wireguard_private_key", true},
	}
	manager := loadOfficeRules(t)
	for _, tc := range cases {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			engine := NewEngine(Options{MaxFileSizeBytes: 10 * mib, MaxReadBytes: 10 * mib}, manager, nil, logx.New("error"))
			size := tc.size
			if size == 0 {
				size = int64(len(tc.content))
			}
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{
				FilePath: tc.path, Name: filepath.Base(tc.path), Extension: filepath.Ext(tc.path), Size: size,
			}, []byte(tc.content))
			for _, finding := range evaluation.Findings {
				for _, ruleID := range append([]string{finding.RuleID}, finding.MatchedRuleIDs...) {
					if ruleID != tc.rule {
						continue
					}
					if finding.Actionable != tc.actionable {
						t.Fatalf("%s actionable=%v, want %v", tc.rule, finding.Actionable, tc.actionable)
					}
					return
				}
			}
			t.Fatalf("%s not reported; findings=%v", tc.rule, ruleIDs(evaluation.Findings))
		})
	}
}

func TestPeerOnlyWireGuardConfigHasNoPrivateKeyFinding(t *testing.T) {
	engine := NewEngine(Options{}, loadOfficeRules(t), nil, logx.New("error"))
	content := "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.synthetic:51820\n"
	evaluation := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: "IT/VPN/peer.conf", Name: "peer.conf", Extension: ".conf", Size: int64(len(content))}, []byte(content))
	if hasRuleID(evaluation.Findings, "content.wireguard_private_key") {
		t.Fatal("public-key-only WireGuard config reported as a private key")
	}
}

// Saved passwords in remote-access client stores are encrypted or encoded.
// They are reported, but never confirmed as plaintext credentials.
func TestRemoteAccessStorePasswordsAreNeverConfirmed(t *testing.T) {
	cases := map[string]string{
		"IT/Tools/mRemoteNG/confCons.xml":      `<mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"><Node Name="dc01" Username="svc_synthetic" Domain="SYNTHETIC" Password="R5SJ0nW0zv9mR4Y3XQf8rJ7nD3gH2kP9uL1qB6tE0wA=" Hostname="dc01.synthetic" /></mrng:Connections>`,
		"IT/Admin/servers.rdg":                 `<RDCMan><file><server><logonCredentials inherit="None"><userName>svc_synthetic</userName><password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAsynthetic0123</password><domain>SYNTHETIC</domain></logonCredentials></server></file></RDCMan>`,
		"Users/Bob/AppData/Roaming/WinSCP.ini": "[Sessions\\svc@files.synthetic]\nHostName=files.synthetic\nUserName=svc_synthetic\nPassword=A35C455A1D6E6D6E6F6F6E6D3B323D3B2E7A6F6C696D\n",
	}
	manager := loadOfficeRules(t)
	for path, content := range cases {
		t.Run(filepath.Base(path), func(t *testing.T) {
			engine := NewEngine(Options{}, manager, nil, logx.New("error"))
			recorder := &recordingCandidateSink{}
			engine.SetCredentialCandidateSink(recorder)
			evaluation := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: path, Name: filepath.Base(path), Extension: filepath.Ext(path), Size: int64(len(content))}, []byte(content))
			for _, candidate := range recorder.candidates {
				if candidate.Verification == credentialanalysis.Confirmed {
					t.Fatalf("encrypted store password confirmed as plaintext: %+v", candidate)
				}
			}
			if _, ok := confirmedCredentialFinding(evaluation.Findings); ok {
				t.Fatal("encrypted store password produced a confirmed-credential finding")
			}
			if !hasRuleID(evaluation.Findings, "content.remote_access_saved_password") {
				t.Fatalf("saved password not reported; findings=%v", ruleIDs(evaluation.Findings))
			}
		})
	}
}

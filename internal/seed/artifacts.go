package seed

import (
	"bytes"
	"fmt"
)

// artifactOversize is just above the scanner's default 10 MiB file size
// limit, so these fixtures exercise the size gate without large uploads.
const artifactOversize = 10*1024*1024 + 512*1024

type artifactFixture struct {
	family, path, format, class, severity, rule, reason string
	content                                             []byte
}

// generateArtifactCorpus creates a deterministic corpus of high-value
// artifacts that must be reported by name or content: virtual disk and memory
// images, memory dumps, Kerberos tickets, remote-access client stores,
// WireGuard keys, mail stores and oversized files. All content is synthetic.
func generateArtifactCorpus(opts GenerateOptions) ([]SeedFile, error) {
	prefix := normalizeSeedPrefix(opts.SeedPrefix)
	fixtures := artifactFixtures()
	files := make([]SeedFile, 0, len(fixtures))
	for index, fixture := range fixtures {
		directory, filename := splitSeedPath(fixture.path)
		file := SeedFile{
			Category:            fixture.family,
			Format:              fixture.format,
			RelativePath:        joinSeedPath(prefix, directory),
			Filename:            filename,
			Content:             fixture.content,
			IntendedAs:          "artifact-coverage",
			ExpectedClass:       fixture.class,
			ExpectedTriageClass: fixture.class,
			ExpectedSeverity:    fixture.severity,
			ExpectedRuleThemes:  []string{fixture.rule},
			ExpectedInspectable: true,
			FixtureID:           fmt.Sprintf("artifact-%03d", index+1),
			SeedVariant:         fixture.family,
			SupportStatus:       "supported",
			NegativeReason:      fixture.reason,
		}
		files = append(files, file)
	}
	return files, nil
}

func splitSeedPath(path string) (string, string) {
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] == '/' {
			return path[:index], path[index+1:]
		}
	}
	return "", path
}

func paddedArtifact(header []byte, size int) []byte {
	content := make([]byte, size)
	copy(content, header)
	return content
}

func artifactFixtures() []artifactFixture {
	sqlHead := "-- synthetic database export\nusername=svc_artifact_sql\npassword=Artifact-Sql-Prefix-41!\n"
	sqlDump := []byte(sqlHead + string(bytes.Repeat([]byte("INSERT INTO audit_log VALUES (1, 'synthetic row');\n"), artifactOversize/52+1)))
	return []artifactFixture{
		// Virtual disk, VM memory and optical images.
		{"disk-images", "Backups/Hyper-V/DC01.vhdx", "vhdx", seedClassActionable, "high", "extension.virtual_disk_and_memory_images", "", paddedArtifact([]byte("vhdxfile"), artifactOversize)},
		{"disk-images", "Backups/VMware/fs01-flat.vmdk", "vmdk", seedClassActionable, "high", "extension.virtual_disk_and_memory_images", "", []byte("# Disk DescriptorFile\nversion=1\nCID=fffffffe\ncreateType=\"monolithicFlat\"\n")},
		{"disk-images", "VMs/fs01/fs01-Snapshot1.vmem", "vmem", seedClassActionable, "high", "extension.virtual_disk_and_memory_images", "", paddedArtifact([]byte("synthetic-vmem"), 4096)},
		{"disk-images", "Exports/appliance.ova", "ova", seedClassActionable, "high", "extension.virtual_disk_and_memory_images", "", paddedArtifact([]byte("synthetic-ova"), 4096)},
		{"disk-images", "ISO/boot-media.iso", "iso", seedClassWeakReview, "medium", "extension.optical_disk_images", "", paddedArtifact([]byte("\x00CD001"), 4096)},
		// Memory dumps.
		{"memory-dumps", "Users/Admin/Desktop/lsass.dmp", "dmp", seedClassActionable, "high", "filename.memory_dump_artifacts", "", paddedArtifact([]byte("MDMP\x93\xa7"), artifactOversize)},
		{"memory-dumps", "Support/Dumps/memory.dmp", "dmp", seedClassActionable, "high", "filename.memory_dump_artifacts", "", paddedArtifact([]byte("PAGEDU64"), 4096)},
		// Kerberos tickets, caches and keytabs (including a cache under a tmp folder).
		{"kerberos", "Users/Admin/tickets/administrator.kirbi", "kirbi", seedClassActionable, "high", "filename.kerberos_ticket_artifacts", "", []byte("\x76\x82\x05\x00synthetic-kirbi")},
		{"kerberos", "Users/Admin/tickets/admin.ccache", "ccache", seedClassActionable, "high", "filename.kerberos_ticket_artifacts", "", []byte("\x05\x04\x00\x0csynthetic-ccache")},
		{"kerberos", "Linux/tmp/krb5cc_1000", "ccache", seedClassActionable, "high", "filename.kerberos_ticket_artifacts", "", []byte("\x05\x04\x00\x0csynthetic-ccache")},
		{"kerberos", "Linux/etc/http.keytab", "keytab", seedClassActionable, "high", "filename.kerberos_ticket_artifacts", "", []byte("\x05\x02\x00\x00synthetic-keytab")},
		// Remote-access client stores with and without saved passwords.
		{"remote-access", "IT/Tools/mRemoteNG/confCons.xml", "xml", seedClassActionable, "high", "content.remote_access_saved_password", "", []byte(`<?xml version="1.0" encoding="utf-8"?><mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" EncryptionEngine="AES" ConfVersion="2.6"><Node Name="dc01" Type="Connection" Username="svc_artifact" Domain="SYNTHETIC" Password="R5SJ0nW0zv9mR4Y3XQf8rJ7nD3gH2kP9uL1qB6tE0wA=" Hostname="dc01.synthetic" Protocol="RDP" /></mrng:Connections>`)},
		{"remote-access", "IT/Tools/mRemoteNG-NoSaved/confCons.xml", "xml", seedClassWeakReview, "medium", "filename.remote_access_client_configs", "no saved password", []byte(`<?xml version="1.0" encoding="utf-8"?><mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" EncryptionEngine="AES" ConfVersion="2.6"><Node Name="dc01" Type="Connection" Username="" Domain="" Password="" Hostname="dc01.synthetic" Protocol="RDP" /></mrng:Connections>`)},
		{"remote-access", "IT/Admin/servers.rdg", "rdg", seedClassActionable, "high", "content.remote_access_saved_password", "", []byte(`<?xml version="1.0" encoding="utf-8"?><RDCMan programVersion="2.7" schemaVersion="3"><file><server><properties><name>srv01.synthetic</name></properties><logonCredentials inherit="None"><userName>svc_artifact</userName><password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAsyntheticArtifact0123</password><domain>SYNTHETIC</domain></logonCredentials></server></file></RDCMan>`)},
		{"remote-access", "Users/Bob/AppData/Roaming/WinSCP.ini", "ini", seedClassActionable, "high", "content.remote_access_saved_password", "", []byte("[Sessions\\svc_artifact@files.synthetic]\nHostName=files.synthetic\nUserName=svc_artifact\nPassword=A35C455A1D6E6D6E6F6F6E6D3B323D3B2E7A6F6C696D\n")},
		{"remote-access", "Users/Bob/AppData/Roaming/FileZilla/sitemanager.xml", "xml", seedClassActionable, "high", "content.remote_access_saved_password", "", []byte(`<?xml version="1.0"?><FileZilla3><Servers><Server><Host>ftp.synthetic</Host><Port>21</Port><User>svc_artifact</User><Pass encoding="base64">U3ludGhldGljLUFydGlmYWN0IQ==</Pass></Server></Servers></FileZilla3>`)},
		{"remote-access", "Users/Bob/Desktop/jump.rdp", "rdp", seedClassActionable, "high", "content.remote_access_saved_password", "", []byte("full address:s:jump.synthetic\nusername:s:SYNTHETIC\\svc_artifact\npassword 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB0100000052A9E191EA75A948B359790578C9371A\n")},
		{"remote-access", "Users/Bob/Desktop/nopass.rdp", "rdp", seedClassWeakReview, "medium", "filename.remote_access_client_configs", "no saved password", []byte("full address:s:jump.synthetic\nusername:s:SYNTHETIC\\svc_artifact\n")},
		// WireGuard.
		{"vpn", "IT/VPN/wg0.conf", "conf", seedClassActionable, "high", "content.wireguard_private_key", "", []byte("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.200.0.2/32\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.synthetic:51820\n")},
		{"vpn", "IT/VPN/peer-only.conf", "conf", "negative", "informational", "content.wireguard_private_key", "public key only", []byte("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.synthetic:51820\nAllowedIPs = 10.200.0.0/24\n")},
		// Mail stores.
		{"mail", "Mail/Archive/old-mail.pst", "pst", seedClassWeakReview, "medium", "extension.mail_store_archives", "", paddedArtifact([]byte("!BDN"), 4096)},
		// Oversized files: name-based findings and prefix reads.
		{"oversized", "Exports/database-dump.sql", "sql", seedClassActionable, "high", "credentialanalysis.confirmed_credential", "", sqlDump},
		{"oversized", "Exports/passwords.xlsx", "xlsx", seedClassWeakReview, "medium", "filename.credentials_and_secrets_keywords", "", paddedArtifact([]byte("PK\x03\x04"), artifactOversize)},
	}
}

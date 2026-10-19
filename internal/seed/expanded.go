package seed

import (
	"fmt"
	"strings"
)

// generateExpanded builds the deterministic, moderately sized recursive corpus
// used for interactive SMB scheduler and resume validation. It deliberately
// keeps fixture content small; traversal volume comes from path breadth.
func generateExpanded(opts GenerateOptions) ([]SeedFile, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 12000
	}
	if opts.Depth < 10 {
		opts.Depth = 12
	}
	prefix := normalizeSeedPrefix(opts.SeedPrefix)
	files := make([]SeedFile, 0, opts.MaxFiles)
	seen := make(map[string]struct{}, opts.MaxFiles)
	add := func(category, directory, filename, format, content string) bool {
		if len(files) >= opts.MaxFiles {
			return false
		}
		relative := joinSeedPath(prefix, directory)
		full := joinSeedPath(relative, filename)
		if _, exists := seen[full]; exists {
			return true
		}
		seen[full] = struct{}{}
		files = append(files, SeedFile{
			Category: category, Format: format, RelativePath: relative,
			Filename: filename, Content: []byte(content), IntendedAs: category,
			ExpectedSeverity: expandedSeverity(category),
		})
		return true
	}

	// Keep the control fixtures early so lower max-files values still include
	// the exact skip and evidence paths.
	for _, fixture := range expandedEvidenceFixtures(prefix) {
		if !add(fixture.category, fixture.directory, fixture.filename, fixture.format, fixture.content) {
			return files, nil
		}
	}
	for _, fixture := range expandedSkipFixtures(prefix) {
		if !add(fixture.category, fixture.directory, fixture.filename, fixture.format, fixture.content) {
			return files, nil
		}
	}
	for index := 0; index < 96; index++ {
		if !add("resume", joinSeedPath("Resume-Test", fmt.Sprintf("Batch-%03d", index/12)), fmt.Sprintf("resume-%03d.txt", index+1), "txt", fmt.Sprintf("resume fixture %03d: benign deterministic content\n", index+1)) {
			return files, nil
		}
	}

	for branch := 1; branch <= 8; branch++ {
		for depth := 1; depth <= opts.Depth; depth++ {
			directory := fmt.Sprintf("DeepTree/Branch-%02d", branch)
			for level := 1; level <= depth; level++ {
				directory = joinSeedPath(directory, fmt.Sprintf("Level-%02d", level))
			}
			for fileIndex := 1; fileIndex <= 12; fileIndex++ {
				_, format := expandedFillerName(fileIndex)
				if !add("deep-tree", directory, fmt.Sprintf("deep-%02d-%03d.%s", depth, fileIndex, format), format, fmt.Sprintf("DeepTree branch %02d level %02d file %03d\n", branch, depth, fileIndex)) {
					return files, nil
				}
			}
		}
	}

	for folder := 1; folder <= 500; folder++ {
		directory := fmt.Sprintf("WideTree/Folder-%04d", folder)
		for fileIndex := 1; fileIndex <= 20; fileIndex++ {
			_, format := expandedFillerName(fileIndex)
			if !add("wide-tree", directory, fmt.Sprintf("wide-%03d.%s", fileIndex, format), format, fmt.Sprintf("WideTree folder %04d file %03d\n", folder, fileIndex)) {
				return files, nil
			}
		}
		for subdir := 1; subdir <= 2; subdir++ {
			for fileIndex := 1; fileIndex <= 8; fileIndex++ {
				_, format := expandedFillerName(fileIndex + subdir)
				if !add("wide-tree", joinSeedPath(directory, fmt.Sprintf("Subtree-%02d", subdir)), fmt.Sprintf("nested-%03d.%s", fileIndex, format), format, fmt.Sprintf("WideTree nested folder %04d/%02d file %03d\n", folder, subdir, fileIndex)) {
					return files, nil
				}
			}
		}
	}
	return files, nil
}

type expandedFixture struct {
	category, directory, filename, format, content string
}

func expandedEvidenceFixtures(_ string) []expandedFixture {
	base := "Evidence-Fixtures"
	return []expandedFixture{
		{"evidence-powershell", joinSeedPath(base, "PowerShell"), "credential-assignment.ps1", "ps1", "$username = 'synthetic-user'\n$password = 'Synthetic-Expanded-Password-001!'\n"},
		{"evidence-shell", joinSeedPath(base, "Shell"), "environment-export.sh", "sh", "export APP_USER=synthetic-user\nexport APP_PASSWORD='Synthetic-Expanded-Password-002!'\n"},
		{"evidence-customsettings", joinSeedPath(base, "Windows"), "CustomSettings.ini", "ini", "[UserData]\nAdminPassword=Synthetic-Expanded-Password-003!\n"},
		{"evidence-unattend", joinSeedPath(base, "Windows"), "unattend.xml", "xml", "<unattend><AdminPassword>Synthetic-Expanded-Password-004!</AdminPassword></unattend>\n"},
		{"evidence-connection", joinSeedPath(base, "Applications"), "app.config", "config", "Server=synthetic-db;User Id=synthetic-user;Password=Synthetic-Expanded-Password-005!;\n"},
		{"evidence-ssh", joinSeedPath(base, "SSH"), "id_rsa", "key", "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-only-key-material\n-----END OPENSSH PRIVATE KEY-----\n"},
		{"evidence-vpn", joinSeedPath(base, "VPN"), "client.ovpn", "ovpn", "client\nremote synthetic-vpn.invalid\nauth-user-pass synthetic-creds.txt\n"},
		{"evidence-aws", joinSeedPath(base, "Cloud"), "credentials", "ini", "[default]\naws_access_key_id = AKIASYNTHETIC000001\naws_secret_access_key = SyntheticAwsSecret0001\n"},
		{"evidence-sqlite", joinSeedPath(base, "SQLite"), "synthetic-credentials.sqlite", "sqlite", "SQLite synthetic credential fixture; no real database secret.\n"},
		{"negative-placeholder", joinSeedPath(base, "Negative"), "placeholder.env", "env", "PASSWORD=<REPLACE_ME>\nTOKEN=example-placeholder\nnot-a-secret=synthetic\n"},
		{"negative-benign", joinSeedPath(base, "Negative"), "readme.txt", "txt", "This is a benign synthetic fixture with no credential material.\n"},
		{"evidence-backup", joinSeedPath(base, "Backups"), "application-backup.conf", "conf", "backup_name=synthetic-app\nbackup_password=Synthetic-Expanded-Password-006!\n"},
		{"evidence-office", joinSeedPath(base, "Office"), "synthetic-notes.docx", "docx", "Synthetic office evidence placeholder for manifest coverage.\n"},
		{"evidence-archive", joinSeedPath(base, "Archives"), "synthetic-evidence.zip", "zip", "Synthetic archive evidence placeholder for manifest coverage.\n"},
		{"evidence-correlation", joinSeedPath(base, "Correlation"), "service.env", "env", "DB_PASSWORD=Synthetic-Expanded-Password-007!\n"},
		{"evidence-correlation", joinSeedPath(base, "Correlation"), "service.properties", "properties", "password=Synthetic-Expanded-Password-008!\n"},
		{"evidence-vpn", joinSeedPath(base, "VPN"), "synthetic-creds.txt", "txt", "synthetic-vpn-user\nSynthetic-Expanded-Password-009!\n"},
		{"negative-masked", joinSeedPath(base, "Negative"), "masked.txt", "txt", "password=********\nsecret=REDACTED\n"},
		{"evidence-browser", joinSeedPath(base, "Browser"), "Login Data", "db", "Synthetic browser credential-store fixture; no real credentials.\n"},
		{"evidence-windows", joinSeedPath(base, "Windows"), "SYSTEM", "hive", "Synthetic Windows artifact fixture; not copied from a host.\n"},
		{"evidence-nt-hash", joinSeedPath(base, "Hashes"), "synthetic-pwdump.txt", "txt", "synthetic-user:1107:aad3b435b51404eeaad3b435b51404ee:00112233445566778899aabbccddeeff\nSYNTHETIC\\svc-backup:1108:aad3b435b51404eeaad3b435b51404ee:ffeeddccbbaa99887766554433221100\n"},
		{"evidence-nt-hash", joinSeedPath(base, "Hashes"), "structured-nt-hashes.json", "json", "{\"username\":\"synthetic-json\",\"rid\":1201,\"nt_hash\":\"11223344556677889900aabbccddeeff\"}\n"},
		{"evidence-nt-hash", joinSeedPath(base, "Hashes"), "structured-nt-hashes.yaml", "yaml", "username: synthetic-yaml\nntlm_hash: 223344556677889900aabbccddeeff11\n"},
		{"evidence-netntlm", joinSeedPath(base, "Hashes"), "synthetic-netntlm.txt", "txt", "synthetic-v1::SYNTHETIC:11223344556677889900aabbccddeeff0011223344556677:ffeeddccbbaa99887766554433221100ffeeddccbbaa9988:a1b2c3d4e5f60718\nsynthetic-v2::SYNTHETIC:a1b2c3d4e5f60718:00112233445566778899aabbccddeeff:01010000000000000102030405060708090a0b0c0d0e0f10\n"},
		{"negative-netntlm", joinSeedPath(base, "Negative"), "netntlm-lookalikes.txt", "txt", "synthetic::SYNTHETIC:short:short:a1b2c3d4e5f60718\nsynthetic::SYNTHETIC:a1b2c3d4e5f60718:00112233445566778899aabbccddeeff:02010000000000000102030405060708\n"},
		{"evidence-sccm", joinSeedPath(base, "SCCM"), "task-sequence.ini", "ini", "OSDJoinAccount=SYNTHETIC\\join-account\nOSDJoinPassword=Synthetic-SCCM-Join-482!\nOSDLocalAdminPassword=Synthetic-SCCM-Admin-482!\n"},
		{"evidence-sccm", joinSeedPath(base, "SCCM"), "task-sequence.json", "json", "{\"OSDJoinAccount\":\"SYNTHETIC\\\\json-join\",\"OSDJoinPassword\":\"Synthetic-SCCM-JSON-482!\",\"OSDLocalAdminPassword\":\"Synthetic-SCCM-JSON-Admin-482!\"}\n"},
		{"evidence-sccm", joinSeedPath(base, "SCCM"), "task-sequence.xml", "xml", "<sequence><step><variable name=\"OSDJoinAccount\" value=\"SYNTHETIC\\join-xml\"/><variable name=\"OSDJoinPassword\" value=\"Synthetic-SCCM-XML-482!\"/></step><step><variable name=\"OSDLocalAdminPassword\" value=\"Synthetic-SCCM-XML-Admin-482!\"/></step></sequence>\n"},
		{"negative-sccm", joinSeedPath(base, "SCCM"), "negative-task-sequence.ini", "ini", "OSDJoinAccount=SYNTHETIC\\reference-only\nOSDJoinPassword=<PASSWORD>\nOSDLocalAdminPassword=********\nEncryptedNetworkAccessAccount=BASE64-ENCODED-SYNTHETIC-BLOB\n; OSDJoinPassword=Synthetic-Comment-482!\n"},
		{"negative-hash", joinSeedPath(base, "Negative"), "hash-lookalikes.txt", "txt", "checksum_md5=00112233445566778899aabbccddeeff\nsha256=00112233445566778899aabbccddeeff\nguid=00112233445566778899aabbccddeeff\nrandom=00112233445566778899aabbccddeeff\n"},
		{category: "evidence-manifest", directory: base, filename: "fixture-version.txt", format: "txt", content: "expanded-smb-fixtures-v1\n"},
	}
}

func expandedSkipFixtures(prefix string) []expandedFixture {
	base := "SkipFolder-Test"
	paths := []string{
		joinSeedPath(base, "1", "2", "3", "Nested-A"),
		joinSeedPath(base, "1", "2", "3", "Nested-B"),
		joinSeedPath(base, "1", "2", "3", "Nested-C"),
		joinSeedPath(base, "1", "2", "30"),
		joinSeedPath(base, "1", "2", "4"),
		joinSeedPath(base, "1", "5"),
		joinSeedPath(base, "OtherBranch"),
	}
	fixtures := make([]expandedFixture, 0, len(paths)*12)
	for pathIndex, directory := range paths {
		for fileIndex := 1; fileIndex <= 12; fileIndex++ {
			fixtures = append(fixtures, expandedFixture{
				category:  "skip-folder",
				directory: directory,
				filename:  fmt.Sprintf("scope-%02d-%02d.txt", pathIndex+1, fileIndex),
				format:    "txt",
				content:   fmt.Sprintf("SkipFolder-Test branch %d file %d; synthetic content.\n", pathIndex+1, fileIndex),
			})
		}
	}
	return fixtures
}

func expandedFillerName(index int) (string, string) {
	formats := []string{"txt", "log", "csv", "json", "xml", "ini", "md"}
	format := formats[index%len(formats)]
	return fmt.Sprintf("filler-%03d.%s", index, format), format
}

func expandedSeverity(category string) string {
	if strings.HasPrefix(category, "evidence-") {
		return "high"
	}
	if strings.HasPrefix(category, "negative-") || category == "wide-tree" || category == "deep-tree" {
		return "low"
	}
	return "medium"
}

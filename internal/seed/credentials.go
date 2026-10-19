package seed

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
)

// generateCredentialCorpus creates a small, deliberately varied corpus for
// measuring username/password recall. It contains inert synthetic text only;
// it never authenticates or contacts a service.
func generateCredentialCorpus(opts GenerateOptions) ([]SeedFile, error) {
	prefix := normalizeSeedPrefix(opts.SeedPrefix)
	if prefix == "" {
		prefix = "Credentials-Finder-V1"
	}
	files := make([]SeedFile, 0, 32)
	add := func(path, format, content, username, password, pairing, origin string, pairs int, archive bool) {
		files = append(files, SeedFile{
			Category: "credentials", Format: format, RelativePath: joinSeedPath(prefix, path), Filename: "", Content: []byte(content),
			IntendedAs: "credential-audit", ExpectedClass: "credential", ExpectedTriageClass: "actionable", ExpectedConfidence: "high",
			ExpectedSeverity: "high", ExpectedUsername: username, ExpectedPassword: password, ExpectedPairing: pairing, ExpectedOrigin: origin,
			ExpectedPairs: pairs, ExpectedObservations: pairs, ExpectedInspectable: true, ExpectedArchive: archive,
		})
	}
	addFile := func(path, format string, content []byte, username, password, pairing, origin string, pairs int, archive bool) {
		files = append(files, SeedFile{
			Category: "credentials", Format: format, RelativePath: joinSeedPath(prefix, path), Filename: "", Content: content,
			IntendedAs: "credential-audit", ExpectedClass: "credential", ExpectedTriageClass: "actionable", ExpectedConfidence: "high",
			ExpectedSeverity: "high", ExpectedUsername: username, ExpectedPassword: password, ExpectedPairing: pairing, ExpectedOrigin: origin,
			ExpectedPairs: pairs, ExpectedObservations: pairs, ExpectedInspectable: true, ExpectedArchive: archive,
		})
	}

	add("domain/domain-qualified.json", "json", `{"account":"SYNTHETIC\\svc-build","password":"Notus1001!","context":"domain deployment"}`+"\n", `SYNTHETIC\\svc-build`, "Notus1001!", "same JSON object", "AD / Domain", 1, false)
	add("domain/upn-and-local.ini", "ini", "[domain]\nusername=svc-upn@synthetic.example\npassword=Komtek2002!\n\n[local]\nuser=local-builder\npass=Local3003!\n", "svc-upn@synthetic.example", "Komtek2002!", "one pair per INI section", "AD / Domain", 2, false)
	add("domain/repeated-observations.txt", "txt", "Primary deployment identity: SYNTHETIC\\svc-build\nPassword: Notus1001!\n", `SYNTHETIC\\svc-build`, "Notus1001!", "explicit adjacent assignment; duplicate of domain-qualified.json", "AD / Domain", 1, false)
	add("operator/notus-komtek.txt", "txt", "Notus1004:Notus1004!\nNotus1005:Komtek1005!\nKomtek1006:Komtek1006!\n", "Notus1004", "Notus1004!", "colon-delimited records; three independent pairs", "Unknown Origin", 3, false)
	add("operator/command-lines.txt", "txt", "tool.exe -u Notus1007 -p Notus1007! --mode check\nclient --username Komtek1008 --password 'Komtek 1008!'\napp --user=Notus1009 --pass=Notus1009!\nnet /user:SYNTHETIC\\svc-net /password:Net1010!\n", "Notus1007", "Notus1007!", "explicit command-line flag pairing; four independent commands", "Unknown Origin", 4, false)

	add("config/settings.ini", "ini", "[service]\nlogin=cfg-user\nsecret=CfgSecret!\n\n[backup]\nuid=backup-user\npwd=BackupSecret!\n", "cfg-user", "CfgSecret!", "same INI section", "Local / Generic", 2, false)
	add("config/objects.json", "json", `{"credentials":[{"user":"json-a","password":"JsonA!"},{"login":"json-b","secret":"JsonB!"}],"unrelated":{"user":"not-a-pair"}}`+"\n", "json-a", "JsonA!", "same JSON object; array contains two pairs", "Unknown Origin", 2, false)
	add("config/records.yaml", "yaml", "accounts:\n  - username: yaml-a\n    password: YamlA!\n  - account: yaml-b\n    passwd: YamlB!\n", "yaml-a", "YamlA!", "same YAML object; two account records", "Unknown Origin", 2, false)
	add("config/task-sequence.xml", "xml", `<task-sequence><step name="Join"><OSDJoinAccount>SYNTHETIC\\join-xml</OSDJoinAccount><OSDJoinPassword>Synthetic-SCCM-XML-482!</OSDJoinPassword></step><step name="Local"><OSDLocalAdminAccount>local-xml</OSDLocalAdminAccount><OSDLocalAdminPassword>Local-XML-483!</OSDLocalAdminPassword></step></task-sequence>`+"\n", `SYNTHETIC\\join-xml`, "Synthetic-SCCM-XML-482!", "same task-sequence step scope", "SCCM / MECM", 2, false)
	add("config/application.toml", "toml", "[database]\nuser = \"toml-user\"\npassword = \"TomlSecret!\"\n", "toml-user", "TomlSecret!", "same TOML table", "Database", 1, false)
	add("config/application.env", "env", "APP_USER=env-user\nAPP_PASSWORD=EnvSecret!\n", "env-user", "EnvSecret!", "same environment configuration", "Web / Application", 1, false)
	add("config/application.properties", "properties", "app.user=properties-user\napp.password=PropertiesSecret!\n", "properties-user", "PropertiesSecret!", "matching namespaced properties", "Web / Application", 1, false)
	add("config/application.config", "config", "<configuration><appSettings><add key=\"user\" value=\"config-user\"/><add key=\"password\" value=\"ConfigSecret!\"/></appSettings></configuration>\n", "config-user", "ConfigSecret!", "same XML appSettings scope", "Web / Application", 1, false)

	add("scripts/powershell.ps1", "ps1", "$User = 'ps-user'\n$Password = 'PowerShellSecret!'\nWrite-Output 'inert synthetic fixture'\n", "ps-user", "PowerShellSecret!", "same PowerShell assignment scope", "Web / Application", 1, false)
	add("scripts/bash.sh", "sh", "user='bash-user'\npassword='BashSecret!'\nprintf '%s' 'inert'\n", "bash-user", "BashSecret!", "same shell assignment scope", "Unknown Origin", 1, false)
	add("scripts/command.cmd", "cmd", "@echo off\nset USERNAME=cmd-user\nset PASSWORD=CmdSecret!\nrem inert fixture\n", "cmd-user", "CmdSecret!", "same batch assignment scope", "Unknown Origin", 1, false)
	add("scripts/python.py", "py", "credentials = {'username': 'python-user', 'password': 'PythonSecret!'}\nprint('inert')\n", "python-user", "PythonSecret!", "same Python dictionary", "Web / Application", 1, false)

	add("databases/sqlserver.config", "config", "Provider=SQLOLEDB;Data Source=sql01.synthetic;Initial Catalog=AuditDb;User ID=sql-user;Password=SqlSecret!;\n", "sql-user", "SqlSecret!", "same SQL Server connection string", "MSSQL / Database", 1, false)
	add("databases/postgres.txt", "txt", "postgresql://pg-user:PgSecret!@pg01.synthetic:5432/audit\n", "pg-user", "PgSecret!", "URI userinfo and database host", "Database", 1, false)
	add("databases/mysql.ini", "ini", "[mysql]\nhost=mysql01.synthetic\nuser=mysql-user\npassword=MySqlSecret!\n", "mysql-user", "MySqlSecret!", "same INI database section", "Database", 1, false)
	add("databases/oracle.properties", "properties", "oracle.user=oracle-user\noracle.password=OracleSecret!\noracle.url=jdbc:oracle:thin:@oracle01.synthetic:1521/AUDIT\n", "oracle-user", "OracleSecret!", "matching Oracle properties", "Database", 1, false)
	add("databases/odbc.dsn", "dsn", "[Audit]\nDriver=Synthetic ODBC\nServer=odbc01.synthetic\nUID=odbc-user\nPWD=OdbcSecret!\n", "odbc-user", "OdbcSecret!", "same ODBC DSN section", "Database", 1, false)
	add("databases/no-password.conf", "config", "server=db-negative.synthetic\nuser=reference-only\npassword=${DB_PASSWORD}\n", "", "", "unresolved variable reference; review/negative", "Database", 0, false)

	add("web/basic-auth.txt", "txt", "Authorization: Basic synthetic-user:BasicSecret!\nService: https://app.synthetic.example\n", "synthetic-user", "BasicSecret!", "explicit decoded test representation, not a token decoder", "Web / Application", 1, false)
	add("web/deployment.json", "json", `{"service":"deploy.synthetic","credentials":{"account":"deploy-user","secret":"DeploySecret!"}}`+"\n", "deploy-user", "DeploySecret!", "same nested credentials object", "Web / Application", 1, false)

	add("documents/credentials.txt", "txt", "Username: doc-user\nPassword: DocumentSecret!\n", "doc-user", "DocumentSecret!", "adjacent labeled fields", "Unknown Origin", 1, false)
	add("documents/credentials.csv", "csv", "account,password\ncsv-a,CsvA!\ncsv-b,CsvB!\n", "csv-a", "CsvA!", "header-defined two-column table", "Unknown Origin", 2, false)
	add("documents/credentials.md", "md", "| username | password |\n|---|---|\n| md-user | MarkdownSecret! |\n", "md-user", "MarkdownSecret!", "header-defined Markdown table", "Unknown Origin", 1, false)
	add("documents/credentials.html", "html", "<table><tr><th>user</th><th>password</th></tr><tr><td>html-user</td><td>HtmlSecret!</td></tr></table>\n", "html-user", "HtmlSecret!", "same HTML table row", "Web / Application", 1, false)

	zipContent, err := credentialZip()
	if err != nil {
		return nil, err
	}
	addFile("archives/credential-bundle.zip", "zip", zipContent, "zip-user", "ZipSecret!", "archive member credentials.ini", "Unknown Origin", 1, true)
	docx, err := officeContainer("word/document.xml", `<w:document><w:body><w:p>username=docx-user password=DocxSecret!</w:p></w:body></w:document>`)
	if err != nil {
		return nil, err
	}
	addFile("documents/credential.docx", "docx", docx, "docx-user", "DocxSecret!", "OOXML document member", "Unknown Origin", 1, true)
	xlsx, err := officeContainer("xl/sharedStrings.xml", `<sst><si><t>xlsx-user</t></si><si><t>XlsxSecret!</t></si></sst>`)
	if err != nil {
		return nil, err
	}
	addFile("documents/credential.xlsx", "xlsx", xlsx, "xlsx-user", "XlsxSecret!", "OOXML shared strings member", "Unknown Origin", 1, true)

	add("hard-pairing/multiple.json", "json", `{"blocks":[{"username":"multi-a","password":"MultiA!","note":"first"},{"username":"multi-b","password":"MultiB!","note":"second"}],"password":"unpaired"}`+"\n", "multi-a", "MultiA!", "two independent objects; unpaired root password", "Unknown Origin", 2, false)
	add("hard-pairing/same-password.json", "json", `[{"username":"same-a","password":"SharedSecret!"},{"username":"same-b","password":"SharedSecret!"}]`+"\n", "same-a", "SharedSecret!", "two identities share value; remain distinct", "Unknown Origin", 2, false)
	add("hard-pairing/unicode.yaml", "yaml", "credentials:\n  username: opérateur\n  password: UnicodeSecret!\n", "opérateur", "UnicodeSecret!", "same YAML object", "Unknown Origin", 1, false)
	add("negative/placeholders.yaml", "yaml", "username: example-user\npassword: CHANGE_ME\nmasked: '********'\ntemplate: '${PASSWORD}'\n", "", "", "placeholder/masked values must remain suppressed", "Review", 0, false)
	add("negative/account-only.json", "json", `{"username":"reference-only","role":"deployment account"}`+"\n", "", "", "account reference without password", "Review", 0, false)
	add("negative/password-only.txt", "txt", "password=orphan-secret\n", "", "", "password without safely established identity", "Review", 0, false)
	add("negative/unrelated.ini", "ini", "[accounts]\nuser=unrelated-user\n\n[defaults]\npassword=unrelated-password\n", "", "", "independent sections must not be paired", "Review", 0, false)
	add("negative/encrypted.xml", "xml", "<credential><user>opaque-user</user><encryptedPassword>BASE64-CIPHERTEXT-NOT-PLAINTEXT</encryptedPassword></credential>\n", "", "", "encrypted/opaque material", "Review", 0, false)
	add("negative/documentation.md", "md", "Example: username=alice password=example-password; never use in production.\n", "", "", "documentation/example control", "Review", 0, false)

	for i := range files {
		if files[i].Filename == "" {
			path := files[i].RelativePath
			index := strings.LastIndex(path, "/")
			files[i].Filename = path[index+1:]
			if index >= 0 {
				files[i].RelativePath = path[:index]
			}
		}
		files[i].ExpectedPath = joinSeedPath(files[i].RelativePath, files[i].Filename)
	}
	return files, nil
}

func credentialZip() ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entries := map[string]string{
		"credentials.ini": "[service]\nusername=zip-user\npassword=ZipSecret!\n",
		"negative.txt":    "username=example-only\npassword=CHANGE_ME\n",
	}
	for name, content := range entries {
		part, err := writer.Create(name)
		if err != nil {
			return nil, fmt.Errorf("create credential archive member: %w", err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("write credential archive member: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close credential archive: %w", err)
	}
	return buffer.Bytes(), nil
}

func officeContainer(member, content string) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, value := range map[string]string{
		"[Content_Types].xml": "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>",
		member:                content,
	} {
		part, err := writer.Create(name)
		if err != nil {
			return nil, fmt.Errorf("create office member: %w", err)
		}
		if _, err := part.Write([]byte(value)); err != nil {
			return nil, fmt.Errorf("write office member: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close office container: %w", err)
	}
	return buffer.Bytes(), nil
}

package seed

import (
	"archive/zip"
	"bytes"
	"fmt"
	"math/rand"
	"strings"
)

// generateCredentialCorpusV2 creates an independent, deterministic corpus for
// blind credential acceptance. Its expected pairs are ground truth only: the
// scanner and Finder never receive this data.
func generateCredentialCorpusV2(opts GenerateOptions) ([]SeedFile, error) {
	prefix := normalizeSeedPrefix(opts.SeedPrefix)
	if prefix == "" {
		prefix = "Credentials-Finder-V2"
	}
	count := opts.MaxFiles
	if count <= 0 {
		count = 360
	}
	if count > 500 {
		count = 500
	}
	if count < 100 {
		return nil, fmt.Errorf("credentials-v2 requires at least 100 files, got %d", count)
	}
	holdoutStart := count * 4 / 5
	rng := rand.New(rand.NewSource(opts.RandomSeed))
	files := make([]SeedFile, 0, count)

	for index := 0; index < count; index++ {
		subset := "evaluation"
		grammarSet := v2EvaluationGrammars
		if index >= holdoutStart {
			subset = "holdout"
			grammarSet = v2HoldoutGrammars
		}
		kind := index % 10
		fixtureID := fmt.Sprintf("v2-%s-%03d", subset, index+1)
		variant := grammarSet[(index+int(opts.RandomSeed))%len(grammarSet)]
		username := v2Username(rng, index)
		password := v2Password(rng, index)
		if index%23 == 0 {
			username, password = "shared-observation", "Shared-V2-Observation!"
		} else if index%31 == 0 {
			username, password = "multi-password-user", fmt.Sprintf("V2-Password-%03d!", index)
		}
		file := SeedFile{
			Category:                     "credentials-v2",
			Format:                       variant.format,
			RelativePath:                 joinSeedPath(prefix, subset, variant.family),
			Filename:                     fmt.Sprintf("%s-%03d.%s", variant.name, index+1, variant.extension),
			IntendedAs:                   "credential-v2-blind-acceptance",
			ExpectedClass:                "credential",
			ExpectedTriageClass:          "review",
			ExpectedConfidence:           "medium",
			ExpectedSeverity:             "medium",
			ExpectedInspectable:          true,
			ExpectedOwner:                "credentials-v2",
			ExpectedFinderCategory:       "credentials",
			ExpectedProvenance:           "source file",
			ExpectedGrouping:             "independent observation",
			ExpectedCorrelationSemantics: "correlation only when explicitly seeded across source files",
			SupportStatus:                "supported",
			ExpectedJustification:        "deterministic credential grammar selected independently of scanner output",
			FixtureID:                    fixtureID,
			Subset:                       subset,
			SeedVariant:                  variant.name,
		}
		if variant.archive {
			member := "nested/credential.txt"
			switch variant.name {
			case "docx-member":
				member = "word/document.xml"
			case "xlsx-member":
				member = "xl/sharedStrings.xml"
			}
			file.ExpectedArchive = true
			file.ExpectedPath = joinSeedPath(file.RelativePath, file.Filename) + "!" + member
		}

		switch {
		case kind < 7:
			file.ExpectedTriageClass = "actionable"
			file.ExpectedConfidence = "high"
			file.ExpectedSeverity = "high"
			file.ExpectedPairsDetail = []ExpectedCredentialPair{{
				ID:            fixtureID + "-pair-1",
				Username:      username,
				Password:      password,
				Pairing:       variant.pairing,
				Origin:        variant.origin,
				SourceContext: variant.context,
			}}
			file.ExpectedUsername = username
			file.ExpectedPassword = password
			file.ExpectedPairing = variant.pairing
			file.ExpectedOrigin = variant.origin
			file.ExpectedPairs = 1
			file.ExpectedObservations = 1
			file.Content = v2PositiveContent(variant, username, password, index)
			if index%17 == 0 && !variant.archive {
				secondUser := fmt.Sprintf("secondary-%03d", index)
				secondPassword := fmt.Sprintf("Secondary-V2-%03d!", index)
				file.ExpectedPairsDetail = append(file.ExpectedPairsDetail, ExpectedCredentialPair{
					ID:            fixtureID + "-pair-2",
					Username:      secondUser,
					Password:      secondPassword,
					Pairing:       "second explicit scoped pair",
					Origin:        "Unknown Origin",
					SourceContext: "multiple independent pairs",
				})
				file.ExpectedPairs = 2
				file.ExpectedObservations = 2
				file.Content = append(file.Content, []byte(fmt.Sprintf("\nsecondary_username=%s\nsecondary_password=%s\n", secondUser, secondPassword))...)
			}
			if variant.archive {
				file.ExpectedArchive = true
			}
		case kind < 9:
			file.ExpectedClass = "negative"
			file.ExpectedTriageClass = "supporting"
			file.ExpectedConfidence = "none"
			file.ExpectedSeverity = "informational"
			file.ExpectedPairs = 0
			file.ExpectedObservations = 0
			file.NegativeReason = v2NegativeReason(index)
			file.Content = v2NegativeContent(index, username, password)
			if variant.archive {
				file.Content = v2Archive([]zipEntry{{"nested/negative.txt", string(file.Content)}, {"nested/readme.txt", "No usable credential is present.\n"}})
			}
		default:
			file.ExpectedClass = "review"
			file.ExpectedTriageClass = "review"
			file.ExpectedConfidence = "low"
			file.ExpectedSeverity = "low"
			file.ExpectedPairs = 0
			file.ExpectedObservations = 0
			file.NegativeReason = "explicit fields exist but their relationship is ambiguous"
			file.Content = v2AmbiguousContent(index, username, password)
			if variant.archive {
				file.Content = v2Archive([]zipEntry{{"nested/ambiguous.txt", string(file.Content)}, {"nested/readme.txt", "Relationship intentionally requires review.\n"}})
			}
		}
		files = append(files, file)
	}
	return files, nil
}

type v2Grammar struct {
	name, family, extension, format, pairing, origin, context string
	archive                                                   bool
}

var v2EvaluationGrammars = []v2Grammar{
	{name: "json-nested", family: "structured", extension: "json", format: "json", pairing: "same nested object", origin: "Application", context: "JSON service configuration"},
	{name: "yaml-scoped", family: "structured", extension: "yaml", format: "yaml", pairing: "same YAML mapping", origin: "Unknown Origin", context: "YAML deployment configuration"},
	{name: "ini-section", family: "structured", extension: "ini", format: "ini", pairing: "same INI section", origin: "Local Account", context: "INI service configuration"},
	{name: "xml-fields", family: "structured", extension: "xml", format: "xml", pairing: "same XML credential element", origin: "AD / Domain", context: "XML deployment configuration"},
	{name: "powershell", family: "scripts", extension: "ps1", format: "powershell", pairing: "same assignment scope", origin: "Application", context: "PowerShell deployment script"},
	{name: "bash-array", family: "scripts", extension: "sh", format: "bash", pairing: "same command argument scope", origin: "Database", context: "Bash deployment script"},
	{name: "cmd-switches", family: "scripts", extension: "cmd", format: "cmd", pairing: "same command invocation", origin: "Windows Service", context: "CMD deployment script"},
	{name: "python-dict", family: "scripts", extension: "py", format: "python", pairing: "same dictionary", origin: "Application", context: "Python deployment script"},
	{name: "sqlserver", family: "database", extension: "config", format: "connection-string", pairing: "same SQL Server connection string", origin: "MSSQL", context: "SQL Server application configuration"},
	{name: "postgres-uri", family: "database", extension: "txt", format: "connection-uri", pairing: "same PostgreSQL URI", origin: "PostgreSQL", context: "PostgreSQL application configuration"},
	{name: "mysql-uri", family: "database", extension: "properties", format: "properties", pairing: "same MySQL connection properties", origin: "MySQL", context: "MySQL application configuration"},
	{name: "odbc", family: "database", extension: "ini", format: "odbc", pairing: "same ODBC section", origin: "Database", context: "ODBC DSN configuration"},
	{name: "basic-auth", family: "web", extension: "conf", format: "web-config", pairing: "same web service block", origin: "Web / Application", context: "Web deployment configuration"},
	{name: "csv-table", family: "documents", extension: "csv", format: "csv", pairing: "same header-defined row", origin: "Unknown Origin", context: "CSV credential table"},
	{name: "zip-member", family: "archives", extension: "zip", format: "zip", pairing: "same archive member", origin: "Unknown Origin", context: "ZIP archive member", archive: true},
	{name: "docx-member", family: "documents", extension: "docx", format: "docx", pairing: "same OOXML member", origin: "Unknown Origin", context: "DOCX document member", archive: true},
}

var v2HoldoutGrammars = []v2Grammar{
	{name: "json-array", family: "holdout-structured", extension: "json", format: "json", pairing: "same array object", origin: "Application", context: "JSON array configuration"},
	{name: "toml-table", family: "holdout-structured", extension: "toml", format: "toml", pairing: "same TOML table", origin: "Unknown Origin", context: "TOML application configuration"},
	{name: "env-prefix", family: "holdout-structured", extension: "env", format: "env", pairing: "same environment scope", origin: "Application", context: "Environment configuration"},
	{name: "properties", family: "holdout-structured", extension: "properties", format: "properties", pairing: "same property group", origin: "Unknown Origin", context: "Properties configuration"},
	{name: "powershell-splat", family: "holdout-scripts", extension: "ps1", format: "powershell", pairing: "same splat parameter map", origin: "Application", context: "PowerShell parameter map"},
	{name: "python-call", family: "holdout-scripts", extension: "py", format: "python", pairing: "same function call", origin: "Application", context: "Python client setup"},
	{name: "jdbc", family: "holdout-database", extension: "properties", format: "jdbc", pairing: "same JDBC property set", origin: "Database", context: "JDBC application configuration"},
	{name: "postgres-query", family: "holdout-database", extension: "md", format: "connection-uri", pairing: "same PostgreSQL URI", origin: "PostgreSQL", context: "Database runbook"},
	{name: "html-form", family: "holdout-web", extension: "html", format: "html", pairing: "same HTML form row", origin: "Web / Application", context: "Web deployment document"},
	{name: "xlsx-member", family: "holdout-documents", extension: "xlsx", format: "xlsx", pairing: "same OOXML member", origin: "Unknown Origin", context: "XLSX shared strings member", archive: true},
	{name: "zip-multi", family: "holdout-archives", extension: "zip", format: "zip", pairing: "same archive member", origin: "Unknown Origin", context: "ZIP archive member", archive: true},
}

func v2Username(rng *rand.Rand, index int) string {
	prefixes := []string{"Notus", "Komtek", "svc", "deploy", "analyst", "build", "operator", "local"}
	prefix := prefixes[rng.Intn(len(prefixes))]
	switch index % 7 {
	case 0:
		return fmt.Sprintf("SYNTHETIC\\%s%d", prefix, 100+rng.Intn(800))
	case 1:
		return fmt.Sprintf("%s%d@example.synthetic", strings.ToLower(prefix), 100+rng.Intn(800))
	case 2:
		return fmt.Sprintf("%s%d", prefix, 100+rng.Intn(800))
	case 3:
		return fmt.Sprintf("svc-%s-%d", strings.ToLower(prefix), 100+rng.Intn(800))
	case 4:
		return fmt.Sprintf("déploiement-%d", 100+rng.Intn(800))
	case 5:
		return fmt.Sprintf("%s_%d", strings.ToLower(prefix), 100+rng.Intn(800))
	default:
		return fmt.Sprintf("synthetic.user.%d", 100+rng.Intn(800))
	}
}

func v2Password(rng *rand.Rand, index int) string {
	adjectives := []string{"Copper", "Harbor", "Juniper", "Orbit", "Quartz", "Velvet", "Cinder", "Meadow"}
	return fmt.Sprintf("%s-%03d-%s!", adjectives[rng.Intn(len(adjectives))], 100+rng.Intn(800), []string{"North", "Delta", "Seven", "Cobalt"}[index%4])
}

func v2PositiveContent(g v2Grammar, user, pass string, index int) []byte {
	switch g.name {
	case "json-nested", "json-array":
		return []byte(fmt.Sprintf(`{"services":[{"account":%q,"secret":%q,"endpoint":"svc-%03d.synthetic"}]}`+"\n", user, pass, index))
	case "yaml-scoped", "toml-table":
		return []byte(fmt.Sprintf("service:\n  login: %s\n  passwd: %s\n  endpoint: svc-%03d.synthetic\n", user, pass, index))
	case "ini-section", "odbc":
		return []byte(fmt.Sprintf("[service_%03d]\nuser = %s\npassword = %s\nserver = db-%03d.synthetic\n", index, user, pass, index))
	case "xml-fields":
		return []byte(fmt.Sprintf("<credential><account>%s</account><password>%s</password><scope>deployment-%03d</scope></credential>\n", user, pass, index))
	case "powershell", "powershell-splat":
		return []byte(fmt.Sprintf("$params = @{ User = '%s'; Password = '%s'; Target = 'svc-%03d.synthetic' }\nInvoke-Deployment @params\n", user, pass, index))
	case "bash-array":
		return []byte(fmt.Sprintf("deploy --region test --user '%s' --password '%s' --endpoint svc-%03d.synthetic\n", user, pass, index))
	case "cmd-switches":
		return []byte(fmt.Sprintf("deploy.exe /user:%s /password:%s /target:svc-%03d.synthetic\r\n", user, pass, index))
	case "python-dict", "python-call":
		return []byte(fmt.Sprintf("client = {\"username\": %q, \"password\": %q, \"host\": \"svc-%03d.synthetic\"}\n", user, pass, index))
	case "sqlserver":
		return []byte(fmt.Sprintf("Server=db-%03d.synthetic;Initial Catalog=app_%03d;User ID=%s;Password=%s;\n", index, index, user, pass))
	case "postgres-uri", "postgres-query":
		return []byte(fmt.Sprintf("postgresql://%s:%s@db-%03d.synthetic:5432/app_%03d\n", user, pass, index, index))
	case "mysql-uri":
		return []byte(fmt.Sprintf("jdbc:mysql://db-%03d.synthetic/app_%03d?user=%s&password=%s\n", index, index, user, pass))
	case "jdbc":
		return []byte(fmt.Sprintf("spring.datasource.url=jdbc:postgresql://db-%03d.synthetic/app_%03d\nspring.datasource.username=%s\nspring.datasource.password=%s\n", index, index, user, pass))
	case "env-prefix":
		return []byte(fmt.Sprintf("APP_USER=%s\nAPP_PASSWORD=%s\nAPP_ENDPOINT=svc-%03d.synthetic\n", user, pass, index))
	case "properties":
		return []byte(fmt.Sprintf("service.account=%s\nservice.secret=%s\nservice.host=svc-%03d.synthetic\n", user, pass, index))
	case "basic-auth":
		return []byte(fmt.Sprintf("[integration]\nusername=%s\npassword=%s\nurl=https://app-%03d.synthetic\n", user, pass, index))
	case "csv-table":
		return []byte(fmt.Sprintf("account,secret,target\n%s,%s,svc-%03d.synthetic\n", user, pass, index))
	case "html-form":
		return []byte(fmt.Sprintf("<form><input name=\"user\" value=%q><input name=\"password\" value=%q></form>\n", user, pass))
	case "zip-member", "zip-multi":
		return v2Archive([]zipEntry{{"nested/credentials.ini", fmt.Sprintf("[service]\nusername=%s\npassword=%s\n", user, pass)}, {"nested/readme.txt", "No credentials in this member.\n"}})
	case "docx-member":
		return v2Office("word/document.xml", fmt.Sprintf("<document><p>account=%s password=%s</p></document>", user, pass))
	case "xlsx-member":
		return v2Office("xl/sharedStrings.xml", fmt.Sprintf("<sst><si><t>%s</t></si><si><t>%s</t></si></sst>", user, pass))
	default:
		return []byte(fmt.Sprintf("username=%s\npassword=%s\n", user, pass))
	}
}

func v2NegativeReason(index int) string {
	reasons := []string{"placeholder or masked value", "unresolved variable", "identity-only reference", "password-only reference", "opaque/encrypted material", "random hex unrelated to credentials", "password policy documentation", "conflicting independent sections", "broken connection string"}
	return reasons[index%len(reasons)]
}

func v2NegativeContent(index int, user, pass string) []byte {
	switch index % 9 {
	case 0:
		return []byte("username=example-user\npassword=CHANGE_ME\nmasked=********\n")
	case 1:
		return []byte("account=reference-only\npassword=${DEPLOY_PASSWORD}\n")
	case 2:
		return []byte("password=orphan-secret\n")
	case 3:
		return []byte("<credential><user>opaque-user</user><encryptedPassword>BASE64-CIPHERTEXT</encryptedPassword></credential>\n")
	case 4:
		return []byte("checksum=0123456789abcdef0123456789abcdef\n")
	case 5:
		return []byte("Password policy: choose a strong password; never store examples.\n")
	case 6:
		return []byte(fmt.Sprintf("[accounts]\nuser=%s\n\n[defaults]\npassword=%s\n", user, pass))
	case 7:
		return []byte("postgresql://:missing-user@db.synthetic/app\n")
	default:
		return []byte("username=\npassword=\n")
	}
}

func v2AmbiguousContent(index int, user, pass string) []byte {
	switch index % 4 {
	case 0:
		return []byte(fmt.Sprintf("user=%s\npassword=%s\nuser=other-%d\npassword=other-secret\n", user, pass, index))
	case 1:
		return []byte(fmt.Sprintf("accounts:\n  - name: %s\n  - name: other-%d\nsecrets:\n  - value: %s\n  - value: unrelated-secret\n", user, index, pass))
	case 2:
		return []byte(fmt.Sprintf("username=%s\nnotes=scope is not stated\npassword=%s\n", user, pass))
	default:
		return []byte(fmt.Sprintf("postgresql://%s@db-%d.synthetic/app\npassword=%s\n", user, index, pass))
	}
}

type zipEntry struct{ name, content string }

func v2Archive(entries []zipEntry) []byte {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		part, _ := writer.Create(entry.name)
		_, _ = part.Write([]byte(entry.content))
	}
	_ = writer.Close()
	return buffer.Bytes()
}

func v2Office(member, content string) []byte {
	return v2Archive([]zipEntry{{"[Content_Types].xml", "<?xml version=\"1.0\"?><Types></Types>"}, {member, content}})
}

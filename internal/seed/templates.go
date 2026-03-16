package seed

import (
	"encoding/json"
	"fmt"
	"strings"
)

var (
	defaultPersonas  = []string{"alice", "bob", "charlie", "david"}
	serviceAccounts  = []string{"svc_backup", "svc_sql", "svc_deploy", "snaffleuser"}
	enterpriseLabels = []string{"prod", "legacy", "finance", "hr", "payroll", "intranet", "ops", "customer", "archive", "deploy"}
)

func defaultTemplates() []templateSpec {
	return []templateSpec{
		newSpec("configs", []string{
			"IT/Admin", "Web/Configs", "Archive/Legacy/App1/Config", "Archive/Legacy/App2/Config", "Old",
		}, []templateVariant{
			likely("web.config", "xml-settings", "high", []string{"content", "filename", "extension"}, []string{"configuration", "credentials"}, []string{"web-config-review", "hardcoded-secret-indicators"}),
			likely("appsettings.json", "appsettings-json", "high", []string{"content", "filename", "extension"}, []string{"configuration", "credentials"}, []string{"config-file-review", "hardcoded-secret-indicators"}),
			possible("db-backup.conf", "config-kv", "medium", []string{"filename", "extension"}, []string{"configuration"}, []string{"config-file-review"}),
			possible("sql-connection.properties", "config-properties", "medium", []string{"content", "filename"}, []string{"configuration", "credentials"}, []string{"database-connection-strings"}),
			noise("scripts-readme.md", "readme-noise", "low", []string{"low-noise"}, []string{"noise-review"}),
			noise("prod-config-old.yml", "config-yaml-benign", "low", []string{"configuration"}, []string{"config-file-review"}),
		}, renderVariant),
		newSpec("deploy", []string{
			"Deploy", "IT/Deploy", "Archive/Legacy/App2/Config", "Old",
		}, []templateVariant{
			likely("deploy.env", "deploy-env", "high", []string{"content", "filename", "extension"}, []string{"deployment", "credentials"}, []string{"deployment-config-review", "hardcoded-secret-indicators"}),
			likely("unattended.xml", "unattend-xml", "high", []string{"content", "filename", "extension"}, []string{"deployment", "credentials"}, []string{"unattended-install", "deployment-config-review"}),
			possible("install-answer.ini", "config-kv", "medium", []string{"filename", "extension"}, []string{"deployment"}, []string{"unattended-install"}),
			possible("deploy-pipeline.json", "deploy-json", "medium", []string{"content", "filename"}, []string{"deployment"}, []string{"deployment-config-review"}),
			noise("deployment-notes.txt", "notes-benign", "low", []string{"notes"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("vpn", []string{
			"IT/Admin", "VPN", "Users/Bob/Documents", "Users/Charlie/Downloads",
		}, []templateVariant{
			likely("vpn-config.txt", "notes-creds", "high", []string{"content", "filename"}, []string{"vpn", "credentials"}, []string{"vpn-config-review", "hardcoded-secret-indicators"}),
			likely("vpn-client.conf", "config-kv", "high", []string{"content", "filename", "extension"}, []string{"vpn", "configuration"}, []string{"vpn-config-review"}),
			possible("remote-access.cfg", "config-kv", "medium", []string{"filename", "extension"}, []string{"vpn"}, []string{"vpn-config-review"}),
			noise("vpn-readme.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("keepass", []string{
			"Users/Alice/Desktop", "Users/Bob/Documents", "Users/Charlie/Downloads", "IT/Admin",
		}, []templateVariant{
			likely("keepass-export.csv", "keepass-csv", "high", []string{"content", "filename"}, []string{"password-manager", "credentials"}, []string{"keepass-filename-review", "password-manager-artifact-review"}),
			possible("vault-notes-old.txt", "notes-creds", "medium", []string{"filename", "path"}, []string{"password-manager"}, []string{"keepass-filename-review"}),
			noise("meeting-notes.md", "meeting-notes", "low", []string{"notes"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("finance", []string{
			"Finance", "Finance/Exports", "Archive", "Old",
		}, []templateVariant{
			likely("finance-share-notes.txt", "notes-creds", "high", []string{"content", "filename"}, []string{"finance", "credentials"}, []string{"hardcoded-secret-indicators", "business-sensitive-review"}),
			possible("customer_export_q1.csv", "csv-export", "medium", []string{"filename", "path"}, []string{"finance", "business-data"}, []string{"export-filename-review", "business-sensitive-review"}),
			possible("payroll-export-2025.csv", "csv-export", "medium", []string{"filename", "path"}, []string{"finance", "business-data"}, []string{"export-filename-review", "payroll-filename-review"}),
			noise("team-contacts.csv", "team-contacts", "low", []string{"noise"}, []string{"noise-review"}),
			noise("project-plan.md", "meeting-notes", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("sql", []string{
			"SQL", "SQL/Backups", "IT/Admin", "Archive/Legacy/App1/Config",
		}, []templateVariant{
			likely("sql-connection.properties", "config-properties", "high", []string{"content", "filename", "extension"}, []string{"configuration", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}),
			likely("db-backup.conf", "config-kv", "high", []string{"content", "filename"}, []string{"sql", "credentials"}, []string{"database-connection-strings"}),
			possible("sql-backup-readme.txt", "notes-service", "medium", []string{"filename"}, []string{"sql"}, []string{"backup-export-naming"}),
			noise("inventory.csv", "inventory-csv", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("cloud", []string{
			"IT/Admin", "Deploy", "Web/Configs", "Archive",
		}, []templateVariant{
			likely("azure-config.yaml", "cloud-yaml", "high", []string{"content", "filename", "extension"}, []string{"cloud", "configuration"}, []string{"cloud-config-exposure", "hardcoded-secret-indicators"}),
			likely("aws-migration-notes.txt", "notes-cloud", "high", []string{"content", "filename"}, []string{"cloud", "credentials"}, []string{"cloud-config-exposure", "api-token-exposure"}),
			possible("aws-config.json", "cloud-json", "medium", []string{"filename", "extension"}, []string{"cloud"}, []string{"cloud-config-exposure"}),
			noise("cloud-readme.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("legacy", []string{
			"Archive/Legacy/App1/Config", "Archive/Legacy/App2/Config", "Old", "Archive",
		}, []templateVariant{
			likely("legacy-app.conf", "legacy-conf", "high", []string{"content", "filename", "extension"}, []string{"legacy", "configuration"}, []string{"legacy-config-review", "hardcoded-secret-indicators"}),
			possible("prod-config-old.yml", "config-yaml-secrets", "medium", []string{"filename", "extension"}, []string{"legacy", "configuration"}, []string{"legacy-config-review"}),
			possible("archive-notes.txt", "notes-service", "medium", []string{"filename", "path"}, []string{"legacy", "archives"}, []string{"archive-review"}),
			noise("changelog.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("user-notes", []string{
			"Users/Alice/Desktop", "Users/Bob/Documents", "Users/Charlie/Downloads", "Users/David/Desktop",
		}, []templateVariant{
			likely("passwords.txt", "notes-creds", "high", []string{"content", "filename"}, []string{"credentials", "notes"}, []string{"hardcoded-secret-indicators", "sensitive-filename-review"}),
			likely("creds-old.txt", "notes-creds", "high", []string{"content", "filename"}, []string{"credentials", "notes"}, []string{"hardcoded-secret-indicators", "sensitive-filename-review"}),
			possible("notes-old-creds.txt", "notes-creds", "medium", []string{"filename", "path"}, []string{"credentials", "notes"}, []string{"sensitive-filename-review"}),
			possible("service-account-notes.txt", "notes-service", "medium", []string{"content", "filename"}, []string{"service-accounts", "notes"}, []string{"hardcoded-secret-indicators"}),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("scripts", []string{
			"IT/Scripts", "IT/Admin", "Deploy", "Backups/Daily",
		}, []templateVariant{
			likely("backup-script.ps1", "script-ps1", "high", []string{"content", "filename", "extension"}, []string{"scripts", "credentials"}, []string{"script-credentials", "admin-script-review"}),
			likely("deploy-users.sh", "script-shell", "high", []string{"content", "filename", "extension"}, []string{"scripts", "credentials"}, []string{"script-credentials"}),
			possible("admin-reset.cmd", "script-batch", "medium", []string{"filename", "extension"}, []string{"scripts"}, []string{"admin-script-review"}),
			noise("scripts-readme.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("temp", []string{
			"Temp", "Old", "Users/Charlie/Downloads", "Users/David/Desktop",
		}, []templateVariant{
			likely("temp-secrets.log", "log-secrets", "high", []string{"content", "filename"}, []string{"logs", "credentials"}, []string{"log-review", "hardcoded-secret-indicators"}),
			possible("debug-export.txt", "notes-cloud", "medium", []string{"filename", "path"}, []string{"temp"}, []string{"export-filename-review"}),
			noise("app-log.log", "log-noise", "low", []string{"noise"}, []string{"noise-review"}),
			noise("deployment-notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("backups", []string{
			"Backups/Daily", "Backups/Monthly", "SQL/Backups", "Archive",
		}, []templateVariant{
			likely("backup-notes.txt", "backup-notes", "high", []string{"content", "filename"}, []string{"backups", "credentials"}, []string{"backup-export-naming", "hardcoded-secret-indicators"}),
			possible("db-backup.conf", "config-kv", "medium", []string{"filename", "path"}, []string{"backups"}, []string{"backup-export-naming"}),
			noise("backup-index.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("service-accounts", []string{
			"IT/Admin", "Deploy", "SQL", "Web/Configs",
		}, []templateVariant{
			likely("service-account-notes.txt", "notes-service", "high", []string{"content", "filename"}, []string{"service-accounts", "credentials"}, []string{"hardcoded-secret-indicators", "admin-script-review"}),
			likely("svc-deploy.env", "deploy-env", "high", []string{"content", "filename", "extension"}, []string{"service-accounts", "credentials"}, []string{"deployment-config-review", "hardcoded-secret-indicators"}),
			possible("account-mapping.txt", "notes-service", "medium", []string{"filename", "path"}, []string{"service-accounts"}, []string{"admin-script-review"}),
			noise("team-service-list.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("noise", []string{
			"IT", "Finance/Exports", "Users/Bob/Documents", "Temp", "Web/Configs",
		}, []templateVariant{
			noise("meeting-notes.md", "meeting-notes", "low", []string{"noise"}, []string{"noise-review"}),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
			noise("inventory.csv", "inventory-csv", "low", []string{"noise"}, []string{"noise-review"}),
			noise("changelog.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
			noise("team-contacts.csv", "team-contacts", "low", []string{"noise"}, []string{"noise-review"}),
			noise("project-plan.md", "meeting-notes", "low", []string{"noise"}, []string{"noise-review"}),
			noise("app-log.log", "log-noise", "low", []string{"noise"}, []string{"noise-review"}),
			noise("deployment-notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
	}
}

func newSpec(category string, dirs []string, variants []templateVariant, render func(renderContext, templateVariant) []byte) templateSpec {
	return templateSpec{
		Category:        category,
		Directories:     dirs,
		Variants:        variants,
		Personas:        defaultPersonas,
		ServiceAccounts: serviceAccounts,
		Labels:          enterpriseLabels,
		Render:          render,
	}
}

func likely(filename, style, severity string, signalTypes, tags, themes []string) templateVariant {
	return templateVariant{
		Filename:            filename,
		Format:              inferFormat(filename),
		IntendedAs:          "likely-hit",
		ExpectedSignalTypes: signalTypes,
		ExpectedTags:        tags,
		ExpectedRuleThemes:  themes,
		ExpectedSeverity:    severity,
		ContentStyle:        style,
	}
}

func possible(filename, style, severity string, signalTypes, tags, themes []string) templateVariant {
	return templateVariant{
		Filename:            filename,
		Format:              inferFormat(filename),
		IntendedAs:          "possible-hit",
		ExpectedSignalTypes: signalTypes,
		ExpectedTags:        tags,
		ExpectedRuleThemes:  themes,
		ExpectedSeverity:    severity,
		ContentStyle:        style,
	}
}

func noise(filename, style, severity string, tags, themes []string) templateVariant {
	return templateVariant{
		Filename:            filename,
		Format:              inferFormat(filename),
		IntendedAs:          "filler/noise",
		ExpectedSignalTypes: []string{},
		ExpectedTags:        tags,
		ExpectedRuleThemes:  themes,
		ExpectedSeverity:    severity,
		ContentStyle:        style,
	}
}

func renderVariant(ctx renderContext, variant templateVariant) []byte {
	switch variant.ContentStyle {
	case "config-kv":
		return text(
			"username="+accountValue(ctx),
			"password="+passwordValue(ctx),
			"api_token="+apiKeyValue(ctx),
			"connection="+connStringValue(ctx),
		)
	case "config-properties":
		return text(
			"db.user="+serviceAccountValue(ctx),
			"db.password="+passwordValue(ctx),
			"db.connection="+connStringValue(ctx),
			"db.note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "config-yaml-secrets":
		return text(
			"service_user: "+serviceAccountValue(ctx),
			"service_password: "+passwordValue(ctx),
			"client_secret: "+clientSecretValue(ctx),
			"lab_note: LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "config-yaml-benign":
		return text(
			"environment: "+ctx.Label,
			"owner: "+personaValue(ctx),
			"comment: SYNTHETIC_CONFIG_ONLY",
		)
	case "appsettings-json":
		return mustJSON(map[string]any{
			"ConnectionStrings": map[string]string{
				"DefaultConnection": connStringValue(ctx),
			},
			"Credentials": map[string]string{
				"UserName":     serviceAccountValue(ctx),
				"Password":     passwordValue(ctx),
				"ClientSecret": clientSecretValue(ctx),
			},
		})
	case "xml-settings":
		return text(
			"<configuration>",
			"  <username>"+serviceAccountValue(ctx)+"</username>",
			"  <password>"+passwordValue(ctx)+"</password>",
			"  <token>"+tokenValue(ctx)+"</token>",
			"</configuration>",
		)
	case "deploy-env":
		return text(
			"DEPLOY_USER="+serviceAccountValue(ctx),
			"DEPLOY_PASSWORD="+passwordValue(ctx),
			"DEPLOY_TOKEN="+tokenValue(ctx),
			"DEPLOY_NOTE=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "deploy-json":
		return mustJSON(map[string]string{
			"deployUser":     serviceAccountValue(ctx),
			"deployPassword": passwordValue(ctx),
			"deployToken":    tokenValue(ctx),
			"environment":    ctx.Label,
		})
	case "unattend-xml":
		return text(
			"<unattend>",
			"  <Username>"+serviceAccountValue(ctx)+"</Username>",
			"  <Password>"+passwordValue(ctx)+"</Password>",
			"  <ProductKey>LAB_ONLY_VALUE_DO_NOT_USE</ProductKey>",
			"</unattend>",
		)
	case "cloud-yaml":
		return text(
			"subscription: demo-"+ctx.Label,
			"client_id: FAKE_API_KEY_ABC123",
			"client_secret: "+clientSecretValue(ctx),
			"tenant_note: LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "cloud-json":
		return mustJSON(map[string]string{
			"aws_access_key_id":     "FAKE_API_KEY_ABC123",
			"aws_secret_access_key": secretValue(ctx),
			"migration_note":        "LAB_ONLY_VALUE_DO_NOT_USE",
		})
	case "notes-creds":
		return text(
			"lab note only",
			"username: "+accountValue(ctx),
			"password: "+passwordValue(ctx),
			"api key: "+apiKeyValue(ctx),
			"token: "+tokenValue(ctx),
		)
	case "notes-service":
		return text(
			"service account notes",
			"account="+serviceAccountValue(ctx),
			"password="+passwordValue(ctx),
			"client_secret="+clientSecretValue(ctx),
			"lab_note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "notes-cloud":
		return text(
			"cloud migration notes",
			"aws_access_key_id=FAKE_API_KEY_ABC123",
			"aws_secret_access_key="+secretValue(ctx),
			"token="+tokenValue(ctx),
			"note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "notes-benign":
		return text(
			"deployment note",
			"owner="+personaValue(ctx),
			"status=planned",
			"comment=SYNTHETIC_ONLY",
		)
	case "backup-notes":
		return text(
			"backup runbook notes",
			"operator="+serviceAccountValue(ctx),
			"password="+passwordValue(ctx),
			"archive_reference="+fakeReference("BACKUP", ctx),
			"note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "script-ps1":
		return text(
			"$SvcUser = \""+serviceAccountValue(ctx)+"\"",
			"$SvcPass = \""+passwordValue(ctx)+"\"",
			"$DeployToken = \""+tokenValue(ctx)+"\"",
			"$Owner = \""+personaValue(ctx)+"\"",
		)
	case "script-shell":
		return text(
			"export RUN_AS="+serviceAccountValue(ctx),
			"export RUN_PASSWORD="+passwordValue(ctx),
			"export RUN_TOKEN="+tokenValue(ctx),
			"export RUN_NOTE=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "script-batch":
		return text(
			"set RUN_AS="+serviceAccountValue(ctx),
			"set RUN_PASSWORD="+passwordValue(ctx),
			"set RUN_TOKEN="+tokenValue(ctx),
			"set RUN_NOTE=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "log-secrets":
		return text(
			"[WARN] synthetic credential-like log entry",
			"user="+serviceAccountValue(ctx),
			"password="+passwordValue(ctx),
			"client_secret="+clientSecretValue(ctx),
			"token="+tokenValue(ctx),
		)
	case "log-noise":
		return text(
			"[INFO] synthetic application log",
			"component=web",
			"owner="+personaValue(ctx),
			"message=deployment completed successfully in lab",
		)
	case "csv-export":
		return text(
			"record_id,owner,comment",
			"1001,"+personaValue(ctx)+",SYNTHETIC_ONLY",
			"1002,demo_user,LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "keepass-csv":
		return text(
			"Title,Username,Password,URL,Notes",
			"Lab VPN,"+personaValue(ctx)+","+passwordValue(ctx)+",https://lab.invalid,SYNTHETIC_ONLY",
			"Lab SQL,"+serviceAccountValue(ctx)+","+passwordValue(ctx)+",https://sql.invalid,NOT_A_REAL_SECRET",
		)
	case "legacy-conf":
		return text(
			"user="+serviceAccountValue(ctx),
			"passwd="+passwordValue(ctx),
			"dsn="+connStringValue(ctx),
			"legacy_note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "meeting-notes":
		return text(
			"Project meeting notes",
			"- owner: "+personaValue(ctx),
			"- status: synthetic planning only",
			"- action: review lab tasks",
		)
	case "inventory-csv":
		return text(
			"asset_id,hostname,owner",
			"ASSET-1001,FS01,"+personaValue(ctx),
			"ASSET-1002,DC01,demo_owner",
		)
	case "team-contacts":
		return text(
			"name,email,team",
			"Alice Example,alice@example.invalid,IT",
			"Bob Example,bob@example.invalid,Finance",
		)
	case "readme-noise":
		return text(
			"This is a synthetic lab file.",
			"Owner: "+personaValue(ctx),
			"Contains no real credentials or data.",
		)
	default:
		return text(
			"synthetic file",
			"owner="+personaValue(ctx),
			"note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	}
}

func inferFormat(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) < 2 {
		return "txt"
	}
	return strings.ToLower(parts[len(parts)-1])
}

func accountValue(ctx renderContext) string {
	if strings.TrimSpace(ctx.Persona) != "" {
		return ctx.Persona
	}
	return "demo_user"
}

func serviceAccountValue(ctx renderContext) string {
	if strings.TrimSpace(ctx.ServiceAccount) != "" {
		return ctx.ServiceAccount
	}
	return "svc_demo"
}

func personaValue(ctx renderContext) string {
	if strings.TrimSpace(ctx.Persona) != "" {
		return ctx.Persona
	}
	return "alice"
}

func passwordValue(ctx renderContext) string {
	return "EXAMPLE_PASSWORD_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func secretValue(ctx renderContext) string {
	return "NOT_A_REAL_SECRET_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func tokenValue(ctx renderContext) string {
	return "TEST_ONLY_TOKEN_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func apiKeyValue(ctx renderContext) string {
	return "FAKE_API_KEY_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func clientSecretValue(ctx renderContext) string {
	return "SAMPLE_CLIENT_SECRET_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func connStringValue(ctx renderContext) string {
	return "DEMO_CONN_STRING_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func fakeReference(prefix string, ctx renderContext) string {
	return prefix + "_" + strings.ToUpper(strings.ReplaceAll(ctx.Token, "_", ""))
}

func text(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func mustJSON(v any) []byte {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return text(
			"snablr_seed_error=true",
			"error=synthetic_json_render_failed",
			"detail="+fmt.Sprintf("%v", err),
		)
	}
	return append(out, '\n')
}

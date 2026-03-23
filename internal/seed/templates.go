package seed

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
)

var (
	defaultPersonas  = []string{"alice", "bob", "charlie", "david"}
	serviceAccounts  = []string{"svc_backup", "svc_sql", "svc_deploy", "snaffleuser"}
	enterpriseLabels = []string{"prod", "legacy", "finance", "hr", "payroll", "intranet", "ops", "customer", "archive", "deploy"}
)

const (
	seedClassConfigOnly               = "config-only"
	seedClassWeakReview               = "weak-review"
	seedClassActionable               = "actionable"
	seedClassCorrelatedHighConfidence = "correlated-high-confidence"

	seedTriageActionable = "actionable"
	seedTriageConfigOnly = "config-only"
	seedTriageWeakReview = "weak-review"
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
		newSpec("database", []string{
			"SQL", "SQL/Backups", "Web/Configs", "Deploy", "IT/Scripts", "Archive/Legacy/App1/Config", "Backups/Daily",
		}, dbTemplateVariants(), renderVariant),
		newSpec("zip-archives", []string{
			"Deploy", "Archive/Legacy/App1/Config", "Backups/Monthly", "IT/Admin", "Finance/Exports", "Old",
		}, archiveTemplateVariants(), renderArchiveVariant),
		newSpec("secret-stores", []string{
			"IT/Admin", "Archive/Legacy", "Backups/Daily", "Old", "Windows/System32/config", "Windows/System32/config/RegBack",
		}, []templateVariant{
			classify(triage(likely("NTDS.DIT", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("NTDS.DIT.bak", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("shadow", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SYSTEM", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store", "windows"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SECURITY", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store", "windows"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SYSTEM.bak", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store", "windows"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SECURITY.old", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store", "windows"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("shadow-notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
			noise("system.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
			noise("system.bak", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("ad-correlation", []string{
			"Recovery/AD",
		}, []templateVariant{
			classify(triage(likely("NTDS.DIT", "secret-store-marker", "high", []string{"filename", "correlation", "path"}, []string{"credentials", "secret-store", "active-directory"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("SYSTEM", "secret-store-marker", "high", []string{"filename"}, []string{"credentials", "secret-store", "windows"}, []string{"secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
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
			"Old", "Users/Charlie/Downloads", "Users/David/Desktop", "Archive",
		}, []templateVariant{
			likely("scratch-notes.txt", "notes-creds", "high", []string{"content"}, []string{"logs", "credentials"}, []string{"log-review", "hardcoded-secret-indicators"}),
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

func dbTemplateVariants() []templateVariant {
	return []templateVariant{
		classify(triage(likely("appsettings.json", "db-appsettings-json", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("web.config", "db-web-config", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely(".env", "db-env", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("finance-prod.dsn", "db-dsn", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings"}), seedTriageActionable), seedClassActionable, "high", false),
		classify(triage(likely("odbc.ini", "db-odbc-ini", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("tnsnames.ora", "db-tnsnames", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database"}, []string{"database-connection-strings"}), seedTriageActionable), seedClassActionable, "high", false),
		classify(triage(likely("db-deploy.ps1", "db-script-ps1", "high", []string{"content", "filename", "extension"}, []string{"scripts", "database", "credentials"}, []string{"script-credentials", "database-connection-strings"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("docker-compose.yml", "db-docker-compose", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("db-prod.backup.bak", "db-backup-marker", "high", []string{"filename", "extension"}, []string{"backups", "database"}, []string{"backup-export-naming"}), seedTriageActionable), seedClassActionable, "high", false),
		classify(triage(likely("billing-archive.dump", "db-backup-marker", "high", []string{"filename", "extension"}, []string{"backups", "database"}, []string{"backup-export-naming"}), seedTriageActionable), seedClassActionable, "high", false),
		classify(triage(likely("oracle-finance-export.dmp", "db-backup-marker", "high", []string{"filename", "extension"}, []string{"backups", "database"}, []string{"backup-export-naming"}), seedTriageActionable), seedClassActionable, "high", false),
		classify(triage(likely("customers-prod.sqlite", "db-local-artifact", "medium", []string{"filename", "extension"}, []string{"database", "artifacts"}, []string{"database-artifact-review"}), seedTriageActionable), seedClassActionable, "medium", false),
		classify(triage(likely("finance-legacy.mdb", "db-local-artifact", "medium", []string{"filename", "extension"}, []string{"database", "artifacts"}, []string{"database-artifact-review"}), seedTriageActionable), seedClassActionable, "medium", false),
		classify(triage(likely("schema-export.sql", "db-sql-dump", "high", []string{"content", "filename", "extension"}, []string{"database", "credentials"}, []string{"database-connection-strings"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
		classify(triage(likely("database.yml", "db-yaml-config-only", "medium", []string{"filename", "extension"}, []string{"configuration", "database"}, []string{"config-file-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(likely("application.properties", "db-properties-config-only", "medium", []string{"filename", "extension"}, []string{"configuration", "database"}, []string{"config-file-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(likely("config.php", "db-config-php-config-only", "medium", []string{"filename", "extension"}, []string{"configuration", "database"}, []string{"config-file-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(possible("db-admin-notes.txt", "db-admin-notes", "medium", []string{"content", "filename"}, []string{"database", "notes"}, []string{"database-connection-strings"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
		classify(triage(possible("deploy-db.py", "db-script-python-placeholder", "medium", []string{"content", "filename", "extension"}, []string{"scripts", "database"}, []string{"script-credentials"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
		classify(triage(likely("k8s-db-secret.yaml", "db-k8s-secret-placeholder", "medium", []string{"filename", "extension"}, []string{"configuration", "database"}, []string{"config-file-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(noise("database-readme.md", "db-readme-noise", "low", []string{"noise"}, []string{"noise-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
	}
}

func archiveTemplateVariants() []templateVariant {
	return []templateVariant{
		archiveInnerPath(classify(triage(likely("deploy-package.zip", "zip-db-env", "high", []string{"content", "filename", "extension"}, []string{"archives", "configuration", "database", "credentials"}, []string{"archive-review", "database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), ".env"),
		archiveInnerPath(classify(triage(likely("legacy-configs.zip", "zip-web-config", "high", []string{"content", "filename", "extension"}, []string{"archives", "configuration", "credentials"}, []string{"archive-review", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassActionable, "high", false), "configs/web.config"),
		archiveInnerPath(classify(triage(possible("deployment-recovery.zip", "zip-unattended", "high", []string{"content", "filename", "extension"}, []string{"archives", "deployment", "credentials"}, []string{"archive-review", "unattended-install"}), seedTriageActionable), seedClassActionable, "high", false), "answers/unattended.xml"),
		archiveInnerPath(classify(triage(possible("old-config-bundle.zip", "zip-config-only", "medium", []string{"filename", "extension"}, []string{"archives", "configuration"}, []string{"archive-review", "config-file-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false), "configs/database.yml"),
		noise("binary-media-bundle.zip", "zip-binary-only", "low", []string{"archives", "noise"}, []string{"archive-review"}),
		noise("nested-export-bundle.zip", "zip-nested-archive", "low", []string{"archives", "noise"}, []string{"archive-review"}),
		noise("oversized-config-export.zip", "zip-oversized", "low", []string{"archives", "noise"}, []string{"archive-review"}),
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

func triage(variant templateVariant, triageClass string) templateVariant {
	variant.ExpectedTriageClass = strings.TrimSpace(triageClass)
	return variant
}

func classify(variant templateVariant, expectedClass, confidence string, correlated bool) templateVariant {
	variant.ExpectedClass = strings.TrimSpace(expectedClass)
	variant.ExpectedConfidence = strings.TrimSpace(confidence)
	variant.ExpectedCorrelated = correlated
	return variant
}

func archiveInnerPath(variant templateVariant, innerPath string) templateVariant {
	variant.ExpectedInnerPath = strings.TrimSpace(strings.ReplaceAll(innerPath, `\`, "/"))
	return variant
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
	case "db-appsettings-json":
		return mustJSON(map[string]any{
			"ConnectionStrings": map[string]string{
				"MainDatabase":      mssqlConnectionStringValue(ctx),
				"ReportingDatabase": postgresConnectionURLValue(ctx),
			},
			"DatabaseAuth": map[string]string{
				"UserName":         dbUserValue(ctx),
				"Password":         dbPasswordValue(ctx),
				"ClientSecret":     clientSecretValue(ctx),
				"BackupPassphrase": backupPasswordValue(ctx),
			},
			"LabNote": "SYNTHETIC_ONLY_DO_NOT_USE",
		})
	case "xml-settings":
		return text(
			"<configuration>",
			"  <username>"+serviceAccountValue(ctx)+"</username>",
			"  <password>"+passwordValue(ctx)+"</password>",
			"  <token>"+tokenValue(ctx)+"</token>",
			"</configuration>",
		)
	case "db-web-config":
		return text(
			"<configuration>",
			"  <connectionStrings>",
			"    <add name=\"PrimaryDb\" connectionString=\""+xmlEscape(mssqlConnectionStringValue(ctx))+"\" providerName=\"System.Data.SqlClient\" />",
			"    <add name=\"AuditDb\" connectionString=\""+xmlEscape(mysqlConnectionStringValue(ctx))+"\" providerName=\"MySql.Data.MySqlClient\" />",
			"  </connectionStrings>",
			"  <appSettings>",
			"    <add key=\"DbUser\" value=\""+xmlEscape(dbUserValue(ctx))+"\" />",
			"    <add key=\"DbPassword\" value=\""+xmlEscape(dbPasswordValue(ctx))+"\" />",
			"    <add key=\"BackupEncryptionPassword\" value=\""+xmlEscape(backupPasswordValue(ctx))+"\" />",
			"  </appSettings>",
			"</configuration>",
		)
	case "deploy-env":
		return text(
			"DEPLOY_USER="+serviceAccountValue(ctx),
			"DEPLOY_PASSWORD="+passwordValue(ctx),
			"DEPLOY_TOKEN="+tokenValue(ctx),
			"DEPLOY_NOTE=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "db-env":
		return text(
			"DB_CONNECTION="+postgresConnectionURLValue(ctx),
			"DB_USERNAME="+dbUserValue(ctx),
			"DB_PASSWORD="+dbPasswordValue(ctx),
			"DB_CLIENT_SECRET="+clientSecretValue(ctx),
			"DB_BACKUP_KEY="+backupPasswordValue(ctx),
			"SQLITE_PATH="+sqliteReferenceValue(ctx),
			"LAB_NOTE=SYNTHETIC_ONLY_DO_NOT_USE",
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
	case "db-dsn":
		return text(
			"[ODBC]",
			"DRIVER=ODBC Driver 18 for SQL Server",
			"SERVER="+dbHostValue(ctx),
			"DATABASE="+dbNameValue(ctx),
			"UID="+dbUserValue(ctx),
			"PWD="+dbPasswordValue(ctx),
			"Description=SYNTHETIC_ONLY_DO_NOT_USE",
		)
	case "db-odbc-ini":
		return text(
			"[finance_reporting]",
			"Driver=ODBC Driver 18 for SQL Server",
			"Server="+dbHostValue(ctx),
			"Database="+dbNameValue(ctx),
			"UID="+dbUserValue(ctx),
			"PWD="+dbPasswordValue(ctx),
			"",
			"[readonly_inventory]",
			"Driver=PostgreSQL Unicode",
			"Server="+dbHostValue(ctx),
			"Database="+dbNameValue(ctx),
			"Port=5432",
		)
	case "db-tnsnames":
		return text(
			"FINANCE_"+strings.ToUpper(ctx.Label)+" =",
			"  (DESCRIPTION =",
			"    (ADDRESS = (PROTOCOL = TCP)(HOST = "+dbHostValue(ctx)+")(PORT = 1521))",
			"    (CONNECT_DATA =",
			"      (SERVICE_NAME = "+oracleServiceValue(ctx)+")",
			"    )",
			"  )",
		)
	case "db-script-ps1":
		return text(
			"$DbConn = \""+mssqlConnectionStringValue(ctx)+"\"",
			"$DbUser = \""+dbUserValue(ctx)+"\"",
			"$DbPassword = \""+dbPasswordValue(ctx)+"\"",
			"$BackupPassphrase = \""+backupPasswordValue(ctx)+"\"",
			"$SqliteReference = \""+sqliteReferenceValue(ctx)+"\"",
		)
	case "db-docker-compose":
		return text(
			"version: '3.8'",
			"services:",
			"  app:",
			"    image: snablr-lab/app:synthetic",
			"    environment:",
			"      APP_DB_URL: "+postgresConnectionURLValue(ctx),
			"      APP_DB_PASSWORD: "+dbPasswordValue(ctx),
			"      APP_CLIENT_SECRET: "+clientSecretValue(ctx),
			"      APP_BACKUP_KEY: "+backupPasswordValue(ctx),
		)
	case "db-sql-dump":
		return text(
			"-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)",
			"-- backup source="+dbHostValue(ctx)+" database="+dbNameValue(ctx),
			"-- admin dsn="+odbcConnectionSummary(ctx),
			"DROP TABLE IF EXISTS demo_accounts;",
			"CREATE TABLE demo_accounts (id INT, username VARCHAR(64));",
			"CREATE TABLE demo_audit (id INT, event_name VARCHAR(64));",
			"LOCK TABLES demo_accounts WRITE;",
			"INSERT INTO demo_accounts VALUES (1, '"+dbUserValue(ctx)+"');",
			"INSERT INTO demo_accounts VALUES (2, 'synthetic_reader');",
			"UNLOCK TABLES;",
		)
	case "db-yaml-config-only":
		return text(
			"default: &default",
			"  adapter: sqlserver",
			"  host: "+dbHostValue(ctx),
			"  database: "+dbNameValue(ctx),
			"  username: <set-me>",
			"  password: <set-me>",
			"  note: SYNTHETIC_CONFIG_ONLY",
		)
	case "db-properties-config-only":
		return text(
			"db.vendor=postgresql",
			"db.host="+dbHostValue(ctx),
			"db.name="+dbNameValue(ctx),
			"db.user=placeholder_user",
			"db.password=changeme",
			"db.note=SYNTHETIC_CONFIG_ONLY",
		)
	case "db-config-php-config-only":
		return text(
			"<?php",
			"$dbHost = '"+dbHostValue(ctx)+"';",
			"$dbName = '"+dbNameValue(ctx)+"';",
			"$dbUser = 'replace_me';",
			"$dbPass = 'replace_me';",
			"$dbDriver = 'sqlsrv';",
		)
	case "db-admin-notes":
		return text(
			"db cutover notes",
			"- primary host: "+dbHostValue(ctx),
			"- dsn profile: finance_reporting",
			"- service account: "+dbUserValue(ctx),
			"- update password in vault before go-live",
			"- backup artifact: "+backupFilenameValue(ctx),
		)
	case "db-script-python-placeholder":
		return text(
			"DB_URL = \"postgresql://placeholder:changeme@"+dbHostValue(ctx)+"/"+dbNameValue(ctx)+"\"",
			"DB_USER = \"placeholder\"",
			"DB_PASSWORD = \"changeme\"",
			"print(\"synthetic deploy helper\")",
		)
	case "db-k8s-secret-placeholder":
		return text(
			"apiVersion: v1",
			"kind: Secret",
			"metadata:",
			"  name: db-bootstrap",
			"stringData:",
			"  DATABASE_URL: \"postgresql://placeholder:changeme@"+dbHostValue(ctx)+"/"+dbNameValue(ctx)+"\"",
			"  DB_PASSWORD: \"changeme\"",
			"  CLIENT_SECRET: \"<set-me>\"",
		)
	case "db-backup-marker":
		return text(
			"SYNTHETIC DATABASE BACKUP MARKER",
			"source="+dbHostValue(ctx),
			"database="+dbNameValue(ctx),
			"backup_label="+backupFilenameValue(ctx),
			"encryption_password_ref="+backupPasswordValue(ctx),
		)
	case "db-local-artifact":
		return text(
			"SYNTHETIC LOCAL DATABASE FILE",
			"database="+dbNameValue(ctx),
			"owner="+dbUserValue(ctx),
			"note=SYNTHETIC_ONLY_DO_NOT_USE",
		)
	case "db-readme-noise":
		return text(
			"Synthetic database migration checklist.",
			"Contains placeholders and operational notes only.",
			"No real credentials or infrastructure details are present.",
		)
	case "secret-store-marker":
		return text(
			"SYNTHETIC SECRET STORE PLACEHOLDER",
			"Purpose: validate exact high-value artifact detection only.",
			"Contains no usable credential material.",
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

type archiveMemberTemplate struct {
	Path         string
	ContentStyle string
	Content      []byte
	Store        bool
}

var archiveTimestamp = time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)

func renderArchiveVariant(ctx renderContext, variant templateVariant) []byte {
	return buildArchiveBytes(ctx, archiveMembersForVariant(ctx, variant))
}

func archiveMembersForVariant(ctx renderContext, variant templateVariant) []archiveMemberTemplate {
	switch variant.ContentStyle {
	case "zip-db-env":
		return []archiveMemberTemplate{
			{Path: ".env", ContentStyle: "db-env"},
			{Path: "configs/web.config", ContentStyle: "db-web-config"},
			{Path: "notes/notes.txt", ContentStyle: "notes-benign"},
		}
	case "zip-web-config":
		return []archiveMemberTemplate{
			{Path: "configs/web.config", ContentStyle: "db-web-config"},
			{Path: "configs/passwords.txt", ContentStyle: "notes-creds"},
			{Path: "docs/readme.md", ContentStyle: "readme-noise"},
		}
	case "zip-unattended":
		return []archiveMemberTemplate{
			{Path: "answers/unattended.xml", ContentStyle: "unattend-xml"},
			{Path: "exports/creds.csv", ContentStyle: "keepass-csv"},
			{Path: "notes/notes.txt", ContentStyle: "notes-service"},
		}
	case "zip-config-only":
		return []archiveMemberTemplate{
			{Path: "configs/database.yml", ContentStyle: "db-yaml-config-only"},
			{Path: "docs/notes.txt", ContentStyle: "notes-benign"},
		}
	case "zip-binary-only":
		return []archiveMemberTemplate{
			{Path: "media/logo.png", Content: append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00}, bytes.Repeat([]byte{0x01}, 256)...), Store: true},
			{Path: "bin/tool.exe", Content: append([]byte("MZ"), bytes.Repeat([]byte{0x00, 0x02, 0x03, 0x04}, 256)...), Store: true},
		}
	case "zip-nested-archive":
		inner := buildArchiveBytes(ctx, []archiveMemberTemplate{
			{Path: "configs/passwords.txt", ContentStyle: "notes-creds"},
		})
		return []archiveMemberTemplate{
			{Path: "nested/inner-archive.zip", Content: inner, Store: true},
			{Path: "docs/readme.md", ContentStyle: "readme-noise"},
		}
	case "zip-oversized":
		return []archiveMemberTemplate{
			{
				Path:    "exports/creds.csv",
				Content: oversizedArchiveText(ctx, 11*1024*1024),
				Store:   true,
			},
		}
	default:
		return []archiveMemberTemplate{
			{Path: "docs/readme.txt", ContentStyle: "readme-noise"},
		}
	}
}

func buildArchiveBytes(ctx renderContext, members []archiveMemberTemplate) []byte {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, member := range members {
		header := &zip.FileHeader{
			Name:     strings.TrimPrefix(strings.ReplaceAll(member.Path, `\`, "/"), "./"),
			Method:   zip.Deflate,
			Modified: archiveTimestamp,
		}
		if member.Store {
			header.Method = zip.Store
		}
		fileWriter, err := writer.CreateHeader(header)
		if err != nil {
			panic(fmt.Sprintf("build archive: create %s: %v", member.Path, err))
		}
		content := member.Content
		if content == nil {
			memberCtx := ctx
			memberCtx.Filename = path.Base(member.Path)
			memberCtx.Format = inferFormat(memberCtx.Filename)
			memberCtx.ContentStyle = member.ContentStyle
			content = renderVariant(memberCtx, templateVariant{
				Filename:     memberCtx.Filename,
				Format:       memberCtx.Format,
				ContentStyle: member.ContentStyle,
			})
		}
		if _, err := fileWriter.Write(content); err != nil {
			panic(fmt.Sprintf("build archive: write %s: %v", member.Path, err))
		}
	}
	if err := writer.Close(); err != nil {
		panic(fmt.Sprintf("build archive: close: %v", err))
	}
	return buf.Bytes()
}

func oversizedArchiveText(ctx renderContext, size int) []byte {
	if size <= 0 {
		return nil
	}
	var builder strings.Builder
	builder.Grow(size + 128)
	builder.WriteString("username,password,token,comment\n")
	index := 0
	for builder.Len() < size {
		builder.WriteString(fmt.Sprintf(
			"%s_%06d,%s_%06d,%s_%06d,SYNTHETIC_ONLY_DO_NOT_USE_%s\n",
			serviceAccountValue(ctx),
			index,
			passwordValue(ctx),
			index,
			tokenValue(ctx),
			index,
			ctx.Token,
		))
		index++
	}
	out := builder.String()
	if len(out) > size {
		out = out[:size]
	}
	return []byte(out)
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

func dbHostValue(ctx renderContext) string {
	label := strings.ToLower(strings.TrimSpace(ctx.Label))
	if label == "" {
		label = "lab"
	}
	return "db-" + label + ".example.invalid"
}

func dbNameValue(ctx renderContext) string {
	label := strings.ToLower(strings.TrimSpace(ctx.Label))
	if label == "" {
		label = "operations"
	}
	return "snablr_" + strings.ReplaceAll(label, "-", "_")
}

func dbUserValue(ctx renderContext) string {
	return serviceAccountValue(ctx) + "_db"
}

func dbPasswordValue(ctx renderContext) string {
	return "FAKE_DB_PASSWORD_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func backupPasswordValue(ctx renderContext) string {
	return "FAKE_BACKUP_KEY_" + strings.ReplaceAll(ctx.Token, "_", "")
}

func sqliteReferenceValue(ctx renderContext) string {
	return "/srv/sqlite/" + dbNameValue(ctx) + ".sqlite"
}

func oracleServiceValue(ctx renderContext) string {
	label := strings.ToUpper(strings.TrimSpace(ctx.Label))
	if label == "" {
		label = "LAB"
	}
	return "SNABLR_" + label
}

func mssqlConnectionStringValue(ctx renderContext) string {
	return "Server=" + dbHostValue(ctx) + ";Database=" + dbNameValue(ctx) + ";User Id=" + dbUserValue(ctx) + ";Password=" + dbPasswordValue(ctx) + ";Encrypt=True;"
}

func mysqlConnectionStringValue(ctx renderContext) string {
	return "Server=" + dbHostValue(ctx) + ";Database=" + dbNameValue(ctx) + ";Uid=" + dbUserValue(ctx) + ";Pwd=" + dbPasswordValue(ctx) + ";"
}

func postgresConnectionURLValue(ctx renderContext) string {
	return "postgresql://" + dbUserValue(ctx) + ":" + dbPasswordValue(ctx) + "@" + dbHostValue(ctx) + "/" + dbNameValue(ctx) + "?sslmode=require"
}

func odbcConnectionSummary(ctx renderContext) string {
	return "Driver={ODBC Driver 18 for SQL Server};Server=" + dbHostValue(ctx) + ";Database=" + dbNameValue(ctx) + ";Uid=" + dbUserValue(ctx) + ";Pwd=" + dbPasswordValue(ctx) + ";"
}

func backupFilenameValue(ctx renderContext) string {
	return dbNameValue(ctx) + "_" + strings.ToLower(ctx.Label) + "_backup"
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
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

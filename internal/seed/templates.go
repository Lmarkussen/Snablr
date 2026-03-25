package seed

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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
		newSpec("private-keys", []string{
			"Users/Alice/.ssh", "IT/Admin/Keys", "VPN/Profiles", "Archive/Legacy/Auth",
		}, []templateVariant{
			classify(triage(likely("id_rsa", "openssh-private-key", "high", []string{"content", "filename"}, []string{"crypto", "keys", "remote-access"}, []string{"private-key-artifact-review", "private-key-header-validation"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("id_ed25519", "openssh-private-key", "high", []string{"content", "filename"}, []string{"crypto", "keys", "remote-access"}, []string{"private-key-artifact-review", "private-key-header-validation"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("identity", "rsa-private-key", "high", []string{"content", "filename"}, []string{"crypto", "keys", "remote-access"}, []string{"private-key-artifact-review", "private-key-header-validation"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("client-admin.ppk", "ppk-artifact", "high", []string{"filename", "extension"}, []string{"remote-access", "vpn", "client-auth"}, []string{"client-auth-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("branch-admin.ovpn", "ovpn-config", "high", []string{"filename", "extension"}, []string{"remote-access", "vpn", "client-auth"}, []string{"client-auth-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(possible("authorized_keys", "authorized-keys", "medium", []string{"filename"}, []string{"remote-access", "ssh", "context"}, []string{"ssh-support-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(possible("known_hosts", "known-hosts", "medium", []string{"filename"}, []string{"remote-access", "ssh", "context"}, []string{"ssh-support-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			noise("ssh-notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("private-key-correlation", []string{
			"Recovery/Keys",
		}, []templateVariant{
			classify(triage(likely("id_rsa", "openssh-private-key", "high", []string{"content", "filename", "correlation", "path"}, []string{"crypto", "keys", "remote-access"}, []string{"private-key-artifact-review", "private-key-header-validation"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("client-admin.ovpn", "ovpn-config", "high", []string{"filename", "extension"}, []string{"remote-access", "vpn", "client-auth"}, []string{"client-auth-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(possible("authorized_keys", "authorized-keys", "medium", []string{"filename"}, []string{"remote-access", "ssh", "context"}, []string{"ssh-support-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("certificate-bundles", []string{
			"VPN/Profiles", "IT/Admin/Keys", "Archive/Legacy/Auth",
		}, []templateVariant{
			classify(triage(likely("corp-admin.pfx", "pkcs12-artifact", "high", []string{"extension", "path"}, []string{"crypto", "remote-access", "certificates", "client-auth"}, []string{"client-auth-artifact-review", "certificate-bundle-review"}), seedTriageActionable), seedClassActionable, "medium", false),
			classify(triage(likely("branch-admin.p12", "pkcs12-artifact", "high", []string{"extension", "path"}, []string{"crypto", "remote-access", "certificates", "client-auth"}, []string{"client-auth-artifact-review", "certificate-bundle-review"}), seedTriageActionable), seedClassActionable, "medium", false),
			classify(triage(possible("certificate-passwords.txt", "notes-cert-password", "high", []string{"content", "filename"}, []string{"credentials", "notes", "client-auth"}, []string{"hardcoded-secret-indicators", "certificate-bundle-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("certificate-correlation", []string{
			"Recovery/Certificates",
		}, []templateVariant{
			classify(triage(likely("corp-admin.pfx", "pkcs12-artifact", "high", []string{"extension", "path", "correlation"}, []string{"crypto", "remote-access", "certificates", "client-auth"}, []string{"client-auth-artifact-review", "certificate-bundle-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("certificate-passwords.txt", "notes-cert-password", "high", []string{"content", "filename"}, []string{"credentials", "notes", "client-auth"}, []string{"hardcoded-secret-indicators", "certificate-bundle-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("windows-credential-stores", []string{
			"Users/Alice/AppData/Roaming/Microsoft/Credentials",
			"Users/Alice/AppData/Local/Microsoft/Vault/4BF4C442",
			"Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-111-222-333-1001",
			"Archive/ProfileCopies/Bob/AppData/Local/Microsoft/Vault/7AC4A290",
			"Backups/UserMigrations/Charlie/AppData/Roaming/Microsoft/Credentials",
			"Backups/UserMigrations/Charlie/AppData/Roaming/Microsoft/Protect/S-1-5-21-444-555-666-1003",
		}, []templateVariant{
			classify(triage(likely("A1B2C3D4", "win-credstore-marker", "high", []string{"filename", "path"}, []string{"windows", "dpapi", "credentials"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("Policy.vpol", "win-credstore-marker", "high", []string{"filename", "path"}, []string{"windows", "dpapi", "vault"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("Preferred", "win-credstore-marker", "high", []string{"filename", "path"}, []string{"windows", "dpapi", "protect"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("windows-credential-correlation", []string{
			"Users/David/AppData/Roaming/Microsoft/Credentials",
			"Users/David/AppData/Roaming/Microsoft/Protect/S-1-5-21-777-888-999-1004",
			"Users/David/AppData/Local/Microsoft/Vault/9F00AB12",
		}, []templateVariant{
			classify(triage(likely("C0FFEEC0", "win-credstore-marker", "high", []string{"filename", "path", "correlation"}, []string{"windows", "dpapi", "credentials"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("masterkey", "win-credstore-marker", "high", []string{"filename", "path"}, []string{"windows", "dpapi", "protect"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("Policy.vpol", "win-credstore-marker", "high", []string{"filename", "path"}, []string{"windows", "dpapi", "vault"}, []string{"windows-credential-store-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("browser-credential-stores", []string{
			"Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release",
			"Users/Bob/AppData/Local/Google/Chrome/User Data/Default",
			"Archive/ProfileCopies/Charlie/AppData/Local/Microsoft/Edge/User Data/Profile 1",
			"Archive/ProfileCopies/Charlie/AppData/Roaming/Mozilla/Firefox/Profiles/efgh.default-release",
		}, []templateVariant{
			classify(triage(likely("logins.json", "browser-login-json", "medium", []string{"filename", "path"}, []string{"browser", "firefox", "credentials"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(likely("key4.db", "browser-key-store", "medium", []string{"filename", "path"}, []string{"browser", "firefox", "credentials"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(likely("Login Data", "browser-login-db", "medium", []string{"filename", "path"}, []string{"browser", "chromium", "credentials"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(likely("Cookies", "browser-cookie-db", "low", []string{"filename", "path"}, []string{"browser", "chromium", "sessions"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			noise("Login Data.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
			noise("logins.json.bak", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("browser-credential-correlation", []string{
			"Users/David/AppData/Roaming/Mozilla/Firefox/Profiles/ijkl.default-release",
			"Users/David/AppData/Local/Google/Chrome/User Data/Default",
		}, []templateVariant{
			classify(triage(likely("logins.json", "browser-login-json", "medium", []string{"filename", "path", "correlation"}, []string{"browser", "firefox", "credentials"}, []string{"browser-credential-store-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("key4.db", "browser-key-store", "medium", []string{"filename", "path"}, []string{"browser", "firefox", "credentials"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(likely("Login Data", "browser-login-db", "medium", []string{"filename", "path", "correlation"}, []string{"browser", "chromium", "credentials"}, []string{"browser-credential-store-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("Cookies", "browser-cookie-db", "low", []string{"filename", "path"}, []string{"browser", "chromium", "sessions"}, []string{"browser-credential-store-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
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
		newSpec("sqlite-databases", []string{
			"Apps/FinancePortal", "Apps/LegacyService", "Users/Alice/AppData/Local", "Temp/Cache",
		}, []templateVariant{
			archiveInnerPath(classify(triage(likely("customers-prod.sqlite", "sqlite-credential-db", "high", []string{"content", "validated"}, []string{"database", "sqlite", "credentials"}, []string{"sqlite-inspection"}), seedTriageActionable), seedClassActionable, "high", false), "::users.password"),
			archiveInnerPath(classify(triage(likely("session-store.db", "sqlite-token-db", "high", []string{"content", "validated"}, []string{"database", "sqlite", "credentials"}, []string{"sqlite-inspection"}), seedTriageActionable), seedClassActionable, "high", false), "::sessions.token"),
			classify(triage(noise("telemetry-cache.db", "sqlite-benign-db", "low", []string{"database", "sqlite", "noise"}, []string{"sqlite-inspection"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		}, renderVariant),
		newSpec("sqlite-correlation", []string{
			"Apps/PayrollPortal",
		}, []templateVariant{
			archiveInnerPath(classify(triage(likely("payroll-cache.sqlite3", "sqlite-correlation-db", "high", []string{"content", "validated", "correlation"}, []string{"database", "sqlite", "credentials"}, []string{"sqlite-inspection"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "::accounts.password"),
			classify(triage(likely(".env", "db-env", "high", []string{"content", "filename", "extension"}, []string{"configuration", "database", "credentials"}, []string{"database-connection-strings", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("zip-archives", []string{
			"Deploy", "Archive/Legacy/App1/Config", "Backups/Monthly", "IT/Admin", "Finance/Exports", "Old",
		}, archiveTemplateVariants(), renderArchiveVariant),
		newSpec("tar-archives", []string{
			"Backups/Linux", "Archive/Configs", "Deploy/Exports", "Users/Alice/Downloads",
		}, tarTemplateVariants(), renderTarVariant),
		newSpec("office-documents", []string{
			"Docs", "Finance", "Presentations", "Archive/Old", "Projects/Migration",
		}, officeTemplateVariants(), renderOfficeVariant),
		newSpec("wim-images", []string{
			"Images", "Deploy/Media", "Archive/SystemImages", "Backups/InstallMedia",
		}, wimTemplateVariants(), renderWIMVariant),
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
		newSpec("backup-exposure", []string{
			"Backups/SystemState/WindowsImageBackup/DC01/Backup 2025-01-01/C/Windows/System32/config",
			"Recovery/System Volume Information/restore-point-17/Windows/System32/config",
			"Archive/SystemCopies/Windows/System32/config/RegBack",
			"Archive/WindowsImageBackup-Notes",
		}, []templateVariant{
			classify(triage(likely("SAM", "secret-store-marker", "high", []string{"filename", "path"}, []string{"backup", "windows", "secret-store"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SYSTEM", "secret-store-marker", "high", []string{"filename", "path"}, []string{"backup", "windows", "secret-store"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SECURITY.old", "secret-store-marker", "high", []string{"filename", "path"}, []string{"backup", "windows", "secret-store"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("readme.txt", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("backup-exposure-correlation", []string{
			"Backups/SystemState/WindowsImageBackup/DC02/Backup 2025-02-14/C/Windows/System32/config",
		}, []templateVariant{
			classify(triage(likely("NTDS.DIT.bak", "secret-store-marker", "high", []string{"filename", "path", "correlation"}, []string{"backup", "windows", "secret-store", "active-directory"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("SYSTEM.bak", "secret-store-marker", "high", []string{"filename", "path"}, []string{"backup", "windows", "secret-store"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("SECURITY.bak", "secret-store-marker", "high", []string{"filename", "path"}, []string{"backup", "windows", "secret-store"}, []string{"backup-exposure-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			noise("notes.txt", "notes-benign", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("cloud", []string{
			"IT/Admin", "Deploy", "Web/Configs", "Archive",
		}, []templateVariant{
			likely("azure-config.yaml", "cloud-yaml", "high", []string{"content", "filename", "extension"}, []string{"cloud", "configuration"}, []string{"cloud-config-exposure", "hardcoded-secret-indicators"}),
			likely("aws-migration-notes.txt", "notes-cloud", "high", []string{"content", "filename"}, []string{"cloud", "credentials"}, []string{"cloud-config-exposure", "api-token-exposure"}),
			possible("aws-config.json", "cloud-json", "medium", []string{"filename", "extension"}, []string{"cloud"}, []string{"cloud-config-exposure"}),
			noise("cloud-readme.md", "readme-noise", "low", []string{"noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("aws-artifacts", []string{
			"Users/Alice/.aws", "Users/Bob/.aws", "Archive/ProfileCopies/Charlie/.aws", "Backups/UserMigrations/David/.aws",
		}, []templateVariant{
			classify(triage(likely("credentials", "aws-credentials-real", "high", []string{"content", "validated", "filename", "path"}, []string{"cloud", "aws", "credentials"}, []string{"aws-credential-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(likely("config", "aws-config-benign", "medium", []string{"filename", "path"}, []string{"cloud", "aws", "configuration"}, []string{"aws-config-artifact-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			classify(triage(possible("credentials.bak", "aws-credentials-real", "high", []string{"content", "validated", "filename", "path"}, []string{"cloud", "aws", "credentials"}, []string{"aws-credential-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false),
			classify(triage(possible("config.bak", "aws-config-role", "medium", []string{"filename", "path"}, []string{"cloud", "aws", "configuration"}, []string{"aws-config-artifact-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			noise("aws-notes.txt", "aws-notes-benign", "low", []string{"cloud", "noise"}, []string{"noise-review"}),
		}, renderVariant),
		newSpec("aws-correlation", []string{
			"Users/Erin/.aws",
		}, []templateVariant{
			classify(triage(likely("credentials", "aws-credentials-real", "high", []string{"content", "validated", "filename", "path", "correlation"}, []string{"cloud", "aws", "credentials"}, []string{"aws-credential-artifact-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true),
			classify(triage(likely("config", "aws-config-role", "medium", []string{"filename", "path"}, []string{"cloud", "aws", "configuration"}, []string{"aws-config-artifact-review"}), seedTriageWeakReview), seedClassWeakReview, "medium", false),
			noise("migration-notes.txt", "aws-notes-benign", "low", []string{"cloud", "noise"}, []string{"noise-review"}),
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
		classify(triage(likely("customers-prod.sqlite", "sqlite-credential-db", "high", []string{"content", "validated"}, []string{"database", "sqlite", "credentials"}, []string{"sqlite-inspection"}), seedTriageActionable), seedClassActionable, "high", false),
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
		archiveInnerPath(classify(triage(likely("ssh-recovery.zip", "zip-private-key-bundle", "high", []string{"content", "filename", "extension", "correlation"}, []string{"archives", "crypto", "keys", "remote-access"}, []string{"archive-review", "private-key-artifact-review", "private-key-header-validation"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "keys/id_rsa"),
		archiveInnerPath(classify(triage(likely("profile-backup.zip", "zip-wincred-profile", "high", []string{"filename", "path", "correlation"}, []string{"archives", "windows", "dpapi", "credentials"}, []string{"archive-review", "windows-credential-store-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234"),
		noise("binary-media-bundle.zip", "zip-binary-only", "low", []string{"archives", "noise"}, []string{"archive-review"}),
		noise("nested-export-bundle.zip", "zip-nested-archive", "low", []string{"archives", "noise"}, []string{"archive-review"}),
		noise("oversized-config-export.zip", "zip-oversized", "low", []string{"archives", "noise"}, []string{"archive-review"}),
	}
}

func officeTemplateVariants() []templateVariant {
	return []templateVariant{
		archiveInnerPath(classify(triage(likely("credentials.docx", "office-docx-credentials", "high", []string{"content", "filename", "extension"}, []string{"documents", "office", "credentials"}, []string{"office-document-review", "hardcoded-secret-indicators"}), seedTriageActionable), seedClassActionable, "high", false), "word/document.xml"),
		archiveInnerPath(classify(triage(likely("db-access.xlsx", "office-xlsx-credentials", "high", []string{"content", "filename", "extension"}, []string{"documents", "office", "database", "credentials"}, []string{"office-document-review", "database-connection-strings"}), seedTriageActionable), seedClassActionable, "high", false), "xl/sharedStrings.xml"),
		archiveInnerPath(classify(triage(likely("vpn-rollout.pptx", "office-pptx-credentials", "high", []string{"content", "filename", "extension"}, []string{"documents", "office", "remote-access"}, []string{"office-document-review", "api-token-exposure"}), seedTriageActionable), seedClassActionable, "high", false), "ppt/slides/slide1.xml"),
		noise("quarterly-update.docx", "office-docx-benign", "low", []string{"documents", "office", "noise"}, []string{"office-document-review"}),
		noise("inventory.xlsx", "office-xlsx-benign", "low", []string{"documents", "office", "noise"}, []string{"office-document-review"}),
		noise("townhall-notes.pptx", "office-pptx-benign", "low", []string{"documents", "office", "noise"}, []string{"office-document-review"}),
	}
}

func tarTemplateVariants() []templateVariant {
	return []templateVariant{
		archiveInnerPath(classify(triage(likely("linux-backup.tar", "tar-shadow-backup", "high", []string{"content", "filename", "extension"}, []string{"archives", "linux", "credentials"}, []string{"archive-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false), "etc/shadow.bak"),
		archiveInnerPath(classify(triage(likely("deploy-configs.tar.gz", "tar-env-configs", "high", []string{"content", "filename", "extension"}, []string{"archives", "configuration", "database", "credentials"}, []string{"archive-review", "database-connection-strings"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "app/.env"),
		archiveInnerPath(classify(triage(likely("ops-recovery.tgz", "tar-private-key-bundle", "high", []string{"content", "filename", "extension", "correlation"}, []string{"archives", "crypto", "keys", "remote-access"}, []string{"archive-review", "private-key-header-validation"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "keys/id_rsa"),
		classify(triage(noise("binary-drop.tar", "tar-binary-only", "low", []string{"archives", "noise"}, []string{"archive-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(noise("nested-backup.tar.gz", "tar-nested-archive", "low", []string{"archives", "noise"}, []string{"archive-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
		classify(triage(noise("oversized-export.tgz", "tar-oversized", "low", []string{"archives", "noise"}, []string{"archive-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
	}
}

func wimTemplateVariants() []templateVariant {
	return []templateVariant{
		archiveInnerPath(classify(triage(likely("domain-backup.wim", "wim-ntds-system", "high", []string{"filename", "correlation"}, []string{"wim", "active-directory", "secret-store"}, []string{"wim-artifact-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassCorrelatedHighConfidence, "high", true), "Windows/NTDS/ntds.dit"),
		archiveInnerPath(classify(triage(likely("repair-media.wim", "wim-hives", "high", []string{"filename"}, []string{"wim", "windows", "secret-store"}, []string{"wim-artifact-review", "secret-store-artifact-review"}), seedTriageActionable), seedClassActionable, "high", false), "Windows/System32/config/SAM"),
		archiveInnerPath(classify(triage(likely("deploy-image.wim", "wim-unattend", "high", []string{"content", "validated"}, []string{"wim", "deployment", "credentials"}, []string{"wim-artifact-review", "unattended-install"}), seedTriageActionable), seedClassActionable, "high", false), "Windows/Panther/unattend.xml"),
		archiveInnerPath(classify(triage(likely("mdt-capture.wim", "wim-mdt", "high", []string{"content", "validated"}, []string{"wim", "deployment", "mdt"}, []string{"wim-artifact-review", "deployment-config-review"}), seedTriageActionable), seedClassActionable, "high", false), "Deploy/Control/bootstrap.ini"),
		classify(triage(noise("reference-image.wim", "wim-benign", "low", []string{"wim", "noise"}, []string{"wim-artifact-review"}), seedTriageConfigOnly), seedClassConfigOnly, "low", false),
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
	case "notes-cert-password":
		return text(
			"certificate import notes",
			"bundle=corp-admin.pfx",
			"password=CertImport!"+strings.ReplaceAll(ctx.Token, "_", ""),
			"owner="+serviceAccountValue(ctx),
		)
	case "notes-cloud":
		return text(
			"cloud migration notes",
			"aws_access_key_id=FAKE_API_KEY_ABC123",
			"aws_secret_access_key="+secretValue(ctx),
			"token="+tokenValue(ctx),
			"note=LAB_ONLY_VALUE_DO_NOT_USE",
		)
	case "aws-credentials-real":
		return text(
			"[default]",
			"aws_access_key_id = "+awsAccessKeyIDValue(ctx),
			"aws_secret_access_key = "+awsSecretAccessKeyValue(ctx),
			"aws_session_token = "+awsSessionTokenValue(ctx),
			"",
			"[ops-admin]",
			"aws_access_key_id = "+awsAccessKeyIDValue(awsDerivedContext(ctx, "ops")),
			"aws_secret_access_key = "+awsSecretAccessKeyValue(awsDerivedContext(ctx, "ops")),
		)
	case "aws-config-benign":
		return text(
			"[default]",
			"region = eu-north-1",
			"output = json",
			"",
			"[profile audit-readonly]",
			"region = eu-west-1",
			"output = table",
			"cli_pager = ",
		)
	case "aws-config-role":
		return text(
			"[default]",
			"region = us-east-1",
			"output = json",
			"",
			"[profile operations-admin]",
			"role_arn = arn:aws:iam::123456789012:role/OperationsAdmin",
			"source_profile = default",
			"region = us-east-1",
		)
	case "aws-notes-benign":
		return text(
			"AWS migration notes",
			"Profile cleanup is pending after the test cutover.",
			"All secrets are supposed to stay in approved secret-management workflows.",
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
	case "sqlite-credential-db", "sqlite-token-db", "sqlite-benign-db", "sqlite-correlation-db":
		return renderSQLiteSeed(variant.ContentStyle, ctx)
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
	case "openssh-private-key":
		return text(
			"-----BEGIN OPENSSH PRIVATE KEY-----",
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEA",
			"LAB_ONLY_SYNTHETIC_PRIVATE_KEY_"+strings.ReplaceAll(ctx.Token, "_", ""),
			"-----END OPENSSH PRIVATE KEY-----",
		)
	case "rsa-private-key":
		return text(
			"-----BEGIN RSA PRIVATE KEY-----",
			"MIIEpAIBAAKCAQEA"+strings.ReplaceAll(ctx.Token, "_", ""),
			"LAB_ONLY_SYNTHETIC_RSA_PRIVATE_KEY",
			"-----END RSA PRIVATE KEY-----",
		)
	case "ppk-artifact":
		return text(
			"PuTTY-User-Key-File-3: ssh-ed25519",
			"Encryption: none",
			"Comment: synthetic-"+ctx.Label+"-"+ctx.Persona,
			"Public-Lines: 2",
			"AAAAC3NzaC1lZDI1NTE5AAAAI"+strings.ReplaceAll(ctx.Token, "_", ""),
			"Private-Lines: 2",
			"AAAAIHN5bnRoZXRpY19wcmtleV9vbmx5X2RvX25vdF91c2U=",
		)
	case "ovpn-config":
		return text(
			"client",
			"dev tun",
			"proto udp",
			"remote vpn-"+ctx.Label+".example.invalid 1194",
			"auth-user-pass creds.txt",
			"key client.key",
			"cert client.crt",
			"remote-cert-tls server",
			"setenv SAFE_NOTE SYNTHETIC_ONLY_DO_NOT_USE",
		)
	case "authorized-keys":
		return text(
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"+strings.ReplaceAll(ctx.Token, "_", "")+" synthetic-"+ctx.Persona,
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"+strings.ReplaceAll(ctx.Token, "_", "")+" synthetic-backup",
		)
	case "known-hosts":
		return text(
			"vpn-"+ctx.Label+".example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"+strings.ReplaceAll(ctx.Token, "_", ""),
			"jump-"+ctx.Label+".example.invalid ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"+strings.ReplaceAll(ctx.Token, "_", ""),
		)
	case "win-credstore-marker":
		return text(
			"SYNTHETIC WINDOWS CREDENTIAL STORE MARKER",
			"Purpose: validate exact Windows credential-store path coverage only.",
			"Contains no usable secrets or decryptable material.",
		)
	case "browser-login-json":
		return mustJSON(map[string]any{
			"logins": []map[string]any{
				{
					"hostname":          "https://portal.example.invalid",
					"encryptedUsername": "LAB_ONLY_SYNTHETIC_BROWSER_BLOB",
					"encryptedPassword": "LAB_ONLY_SYNTHETIC_BROWSER_BLOB",
					"timeCreated":       "1700000000000",
				},
			},
			"nextId": 2,
		})
	case "browser-key-store":
		return text(
			"SYNTHETIC FIREFOX KEY STORE MARKER",
			"Purpose: validate exact Firefox profile artifact detection only.",
			"Contains no usable browser secrets.",
		)
	case "browser-login-db":
		return text(
			"SYNTHETIC CHROMIUM LOGIN DATA MARKER",
			"Purpose: validate exact Chromium-family profile artifact detection only.",
			"Contains no usable browser credentials.",
		)
	case "browser-cookie-db":
		return text(
			"SYNTHETIC CHROMIUM COOKIES MARKER",
			"Purpose: validate exact Chromium-family session-store artifact detection only.",
			"Contains no usable browser cookies.",
		)
	case "pkcs12-artifact":
		return append([]byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01}, text(
			"SYNTHETIC PKCS12 BUNDLE",
			"Purpose: validate exact .pfx/.p12 artifact detection only.",
			"Contains no usable certificate material.",
		)...)
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

func renderTarVariant(ctx renderContext, variant templateVariant) []byte {
	return buildTARBytes(ctx, tarMembersForVariant(ctx, variant))
}

func renderOfficeVariant(ctx renderContext, variant templateVariant) []byte {
	return buildArchiveBytes(ctx, officeMembersForVariant(ctx, variant))
}

func renderWIMVariant(ctx renderContext, variant templateVariant) []byte {
	return buildWIMBytes(ctx, wimMembersForVariant(ctx, variant))
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
	case "zip-private-key-bundle":
		return []archiveMemberTemplate{
			{Path: "keys/id_rsa", ContentStyle: "openssh-private-key"},
			{Path: "vpn/client-admin.ovpn", ContentStyle: "ovpn-config"},
			{Path: "ssh/known_hosts", ContentStyle: "known-hosts"},
		}
	case "zip-wincred-profile":
		return []archiveMemberTemplate{
			{Path: "Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234", ContentStyle: "win-credstore-marker"},
			{Path: "Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21-111-222-333-1001/masterkey", ContentStyle: "win-credstore-marker"},
			{Path: "Users/Alice/AppData/Local/Microsoft/Vault/4BF4C442/Policy.vpol", ContentStyle: "win-credstore-marker"},
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

func tarMembersForVariant(ctx renderContext, variant templateVariant) []archiveMemberTemplate {
	switch variant.ContentStyle {
	case "tar-shadow-backup":
		return []archiveMemberTemplate{
			{Path: "etc/shadow.bak", Content: []byte("root:$6$synthetic$abcdefghijklmnopqrstuvwx:19000:0:99999:7:::\n")},
			{Path: "etc/passwd", Content: []byte("root:x:0:0:root:/root:/bin/bash\n")},
			{Path: "docs/readme.txt", ContentStyle: "readme-noise"},
		}
	case "tar-env-configs":
		return []archiveMemberTemplate{
			{Path: "app/.env", ContentStyle: "db-env"},
			{Path: "app/config.ini", ContentStyle: "config-kv"},
			{Path: "notes/deploy.txt", ContentStyle: "notes-service"},
		}
	case "tar-private-key-bundle":
		return []archiveMemberTemplate{
			{Path: "keys/id_rsa", ContentStyle: "openssh-private-key"},
			{Path: "vpn/client-admin.ovpn", ContentStyle: "ovpn-config"},
			{Path: "ssh/authorized_keys", ContentStyle: "authorized-keys"},
		}
	case "tar-binary-only":
		return []archiveMemberTemplate{
			{Path: "bin/tool.exe", Content: append([]byte("MZ"), bytes.Repeat([]byte{0x00, 0x02, 0x03, 0x04}, 256)...), Store: true},
			{Path: "media/logo.png", Content: append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00}, bytes.Repeat([]byte{0x01}, 256)...), Store: true},
		}
	case "tar-nested-archive":
		inner := buildTARBytes(ctx, []archiveMemberTemplate{
			{Path: "configs/passwords.txt", ContentStyle: "notes-creds"},
		})
		return []archiveMemberTemplate{
			{Path: "nested/inner.tar", Content: inner, Store: true},
			{Path: "docs/readme.txt", ContentStyle: "readme-noise"},
		}
	case "tar-oversized":
		return []archiveMemberTemplate{
			{Path: "exports/creds.txt", Content: oversizedArchiveText(ctx, 11*1024*1024), Store: true},
		}
	default:
		return []archiveMemberTemplate{
			{Path: "docs/readme.txt", ContentStyle: "readme-noise"},
		}
	}
}

func officeMembersForVariant(ctx renderContext, variant templateVariant) []archiveMemberTemplate {
	switch variant.ContentStyle {
	case "office-docx-credentials":
		return append(officeBaseMembers(".docx"), archiveMemberTemplate{
			Path: "word/document.xml",
			Content: officeDocumentXML(
				"Migration credential notes",
				"service_account="+serviceAccountValue(ctx),
				"password="+dbPasswordValue(ctx),
				"client_secret="+clientSecretValue(ctx),
				mssqlConnectionStringValue(ctx),
			),
		})
	case "office-xlsx-credentials":
		return append(officeBaseMembers(".xlsx"),
			archiveMemberTemplate{
				Path: "xl/sharedStrings.xml",
				Content: officeSharedStringsXML(
					"db_user="+dbUserValue(ctx),
					"db_password="+dbPasswordValue(ctx),
					"client_secret="+clientSecretValue(ctx),
					postgresConnectionURLValue(ctx),
				),
			},
			archiveMemberTemplate{
				Path:    "xl/worksheets/sheet1.xml",
				Content: officeWorksheetXML(3),
			},
		)
	case "office-pptx-credentials":
		return append(officeBaseMembers(".pptx"), archiveMemberTemplate{
			Path: "ppt/slides/slide1.xml",
			Content: officeSlideXML(
				"VPN rollout",
				"remote=vpn-"+ctx.Label+".example.invalid",
				"shared_secret="+clientSecretValue(ctx),
				"password="+dbPasswordValue(ctx),
			),
		})
	case "office-docx-benign":
		return append(officeBaseMembers(".docx"), archiveMemberTemplate{
			Path: "word/document.xml",
			Content: officeDocumentXML(
				"Quarterly update",
				"Owner: "+personaValue(ctx),
				"Status: on track",
			),
		})
	case "office-xlsx-benign":
		return append(officeBaseMembers(".xlsx"),
			archiveMemberTemplate{
				Path:    "xl/sharedStrings.xml",
				Content: officeSharedStringsXML("Q1", "Q2", "Owner", personaValue(ctx)),
			},
			archiveMemberTemplate{
				Path:    "xl/worksheets/sheet1.xml",
				Content: officeWorksheetXML(4),
			},
		)
	case "office-pptx-benign":
		return append(officeBaseMembers(".pptx"), archiveMemberTemplate{
			Path: "ppt/slides/slide1.xml",
			Content: officeSlideXML(
				"Town hall",
				"Agenda",
				"Synthetic lab presentation only",
			),
		})
	default:
		return append(officeBaseMembers(".docx"), archiveMemberTemplate{
			Path:    "word/document.xml",
			Content: officeDocumentXML("Synthetic document"),
		})
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

func buildTARBytes(ctx renderContext, members []archiveMemberTemplate) []byte {
	var archiveBuf bytes.Buffer
	tw := tar.NewWriter(&archiveBuf)
	for _, member := range members {
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
		header := &tar.Header{
			Name:     strings.TrimPrefix(strings.ReplaceAll(member.Path, `\`, "/"), "./"),
			Mode:     0o644,
			Size:     int64(len(content)),
			ModTime:  archiveTimestamp,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			panic(fmt.Sprintf("build tar: write header %s: %v", member.Path, err))
		}
		if _, err := tw.Write(content); err != nil {
			panic(fmt.Sprintf("build tar: write %s: %v", member.Path, err))
		}
	}
	if err := tw.Close(); err != nil {
		panic(fmt.Sprintf("build tar: close: %v", err))
	}

	if strings.HasSuffix(strings.ToLower(ctx.Filename), ".tar.gz") || strings.HasSuffix(strings.ToLower(ctx.Filename), ".tgz") {
		var gzipBuf bytes.Buffer
		gw, err := gzip.NewWriterLevel(&gzipBuf, gzip.NoCompression)
		if err != nil {
			panic(fmt.Sprintf("build tar gzip: create: %v", err))
		}
		gw.Name = ctx.Filename
		gw.ModTime = archiveTimestamp
		if _, err := gw.Write(archiveBuf.Bytes()); err != nil {
			panic(fmt.Sprintf("build tar gzip: write: %v", err))
		}
		if err := gw.Close(); err != nil {
			panic(fmt.Sprintf("build tar gzip: close: %v", err))
		}
		return gzipBuf.Bytes()
	}

	return archiveBuf.Bytes()
}

func officeBaseMembers(ext string) []archiveMemberTemplate {
	switch ext {
	case ".docx":
		return []archiveMemberTemplate{
			{Path: "[Content_Types].xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`)},
			{Path: "_rels/.rels", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`)},
			{Path: "docProps/core.xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Synthetic Office Seed</dc:title></cp:coreProperties>`)},
		}
	case ".xlsx":
		return []archiveMemberTemplate{
			{Path: "[Content_Types].xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`)},
			{Path: "_rels/.rels", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`)},
			{Path: "xl/workbook.xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"></workbook>`)},
		}
	case ".pptx":
		return []archiveMemberTemplate{
			{Path: "[Content_Types].xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`)},
			{Path: "_rels/.rels", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`)},
			{Path: "ppt/presentation.xml", Content: []byte(`<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"></p:presentation>`)},
		}
	default:
		return nil
	}
}

func officeDocumentXML(lines ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, line := range lines {
		b.WriteString(`<w:p><w:r><w:t>`)
		b.WriteString(xmlEscape(line))
		b.WriteString(`</w:t></w:r></w:p>`)
	}
	b.WriteString(`</w:body></w:document>`)
	return []byte(b.String())
}

func officeSharedStringsXML(values ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	for _, value := range values {
		b.WriteString(`<si><t>`)
		b.WriteString(xmlEscape(value))
		b.WriteString(`</t></si>`)
	}
	b.WriteString(`</sst>`)
	return []byte(b.String())
}

func officeWorksheetXML(sharedStringCount int) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">`)
	for idx := 0; idx < sharedStringCount; idx++ {
		b.WriteString(`<c t="s"><v>`)
		b.WriteString(fmt.Sprintf("%d", idx))
		b.WriteString(`</v></c>`)
	}
	b.WriteString(`</row></sheetData></worksheet>`)
	return []byte(b.String())
}

func officeSlideXML(lines ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree>`)
	for _, line := range lines {
		b.WriteString(`<p:sp><p:txBody><a:p><a:r><a:t>`)
		b.WriteString(xmlEscape(line))
		b.WriteString(`</a:t></a:r></a:p></p:txBody></p:sp>`)
	}
	b.WriteString(`</p:spTree></p:cSld></p:sld>`)
	return []byte(b.String())
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
	lower := strings.ToLower(strings.TrimSpace(filename))
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tgz"):
		return "tgz"
	default:
		parts := strings.Split(filename, ".")
		if len(parts) < 2 {
			return "txt"
		}
		return strings.ToLower(parts[len(parts)-1])
	}
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

func awsAccessKeyIDValue(ctx renderContext) string {
	token := strings.ToUpper(strings.ReplaceAll(ctx.Token, "_", ""))
	if len(token) < 16 {
		token += strings.Repeat("A", 16-len(token))
	}
	return "AKIA" + token[:16]
}

func awsSecretAccessKeyValue(ctx renderContext) string {
	base := "ABcdEFghIJklMNopQRstUVwxYZ0123456789/+"
	token := strings.ReplaceAll(ctx.Token, "_", "")
	if token == "" {
		token = "SNABLRAWS"
	}
	combined := strings.Repeat(base+token, 3)
	return combined[:40]
}

func awsSessionTokenValue(ctx renderContext) string {
	token := strings.ReplaceAll(strings.ToUpper(ctx.Token), "_", "")
	if token == "" {
		token = "SNABLRSESSION"
	}
	return "IQoJb3JpZ2luX2VjEKD//////////wEaCXVzLWVhc3QtMSJHMEUC" + token + "A1BC2DE3FG4HI5JK6LM7NO8PQ9RS"
}

func awsDerivedContext(ctx renderContext, suffix string) renderContext {
	derived := ctx
	if strings.TrimSpace(suffix) == "" {
		return derived
	}
	derived.Token = ctx.Token + "_" + suffix
	return derived
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

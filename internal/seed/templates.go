package seed

import (
	"encoding/json"
	"fmt"
	"strings"
)

func defaultTemplates() []templateSpec {
	return []templateSpec{
		{
			Category:           "config",
			Formats:            []string{"ini", "conf", "cfg", "properties", "env", "txt"},
			Directories:        []string{"Config", "Web", "IT", "Users/Alice"},
			FilenamePrefixes:   []string{"appsettings", "service_runtime", "prod_config", "web_settings", "legacy_override"},
			ExpectedTags:       []string{"configuration", "credentials"},
			ExpectedRuleThemes: []string{"hardcoded-secret-indicators", "config-file-review", "sensitive-filename-review"},
			ExpectedSeverity:   "high",
			Render:             renderConfig,
		},
		{
			Category:           "script",
			Formats:            []string{"ps1", "bat", "cmd", "sh", "md", "log"},
			Directories:        []string{"IT/Scripts", "IT/Admin", "Users/Bob", "Temp"},
			FilenamePrefixes:   []string{"helpdesk_reset", "sync_admin_users", "weekly_access_audit", "rotate_demo_passwords"},
			ExpectedTags:       []string{"scripts", "credentials"},
			ExpectedRuleThemes: []string{"script-credentials", "hardcoded-secret-indicators", "admin-script-review"},
			ExpectedSeverity:   "high",
			Render:             renderScript,
		},
		{
			Category:           "backup",
			Formats:            []string{"ps1", "sh", "cmd", "log", "txt", "md"},
			Directories:        []string{"Backups", "Archive", "Old", "Finance"},
			FilenamePrefixes:   []string{"nightly_backup_finance", "archive_payroll", "legacy_export_copy", "retention_backup_index"},
			ExpectedTags:       []string{"archives", "scripts"},
			ExpectedRuleThemes: []string{"backup-export-naming", "script-credentials", "retention-review"},
			ExpectedSeverity:   "medium",
			Render:             renderBackup,
		},
		{
			Category:           "database",
			Formats:            []string{"sql", "conf", "json", "properties", "cfg", "txt"},
			Directories:        []string{"SQL", "Config", "Finance", "Web"},
			FilenamePrefixes:   []string{"reporting_db", "payroll_connection", "finance_sql_runtime", "webapp_dsn"},
			ExpectedTags:       []string{"configuration", "credentials"},
			ExpectedRuleThemes: []string{"database-connection-strings", "hardcoded-secret-indicators", "config-file-review"},
			ExpectedSeverity:   "high",
			Render:             renderDatabase,
		},
		{
			Category:           "web",
			Formats:            []string{"json", "yaml", "yml", "xml", "env", "conf"},
			Directories:        []string{"Web", "Config", "Deploy", "Archive"},
			FilenamePrefixes:   []string{"web_config", "prod_site_settings", "api_runtime", "frontend_release"},
			ExpectedTags:       []string{"configuration", "cloud"},
			ExpectedRuleThemes: []string{"api-token-exposure", "hardcoded-secret-indicators", "web-config-review"},
			ExpectedSeverity:   "high",
			Render:             renderWeb,
		},
		{
			Category:           "hr",
			Formats:            []string{"csv", "txt", "md", "xlsx"},
			Directories:        []string{"HR", "Archive", "Users/Alice"},
			FilenamePrefixes:   []string{"employee_directory", "onboarding_notes", "benefits_export", "hr_review_pack"},
			ExpectedTags:       []string{"pii", "business-data"},
			ExpectedRuleThemes: []string{"pii-sensitive-business-review", "hr-filename-review", "export-filename-review"},
			ExpectedSeverity:   "medium",
			Render:             renderHR,
		},
		{
			Category:           "finance",
			Formats:            []string{"csv", "txt", "md", "xlsx", "docx"},
			Directories:        []string{"Finance", "Archive", "Old"},
			FilenamePrefixes:   []string{"invoice_extract", "quarterly_finance_export", "expense_report_backup", "budget_review_pack"},
			ExpectedTags:       []string{"business-data", "finance"},
			ExpectedRuleThemes: []string{"finance-filename-review", "export-filename-review", "business-sensitive-review"},
			ExpectedSeverity:   "medium",
			Render:             renderFinance,
		},
		{
			Category:           "payroll",
			Formats:            []string{"csv", "txt", "xlsx", "xml", "conf"},
			Directories:        []string{"Payroll", "Archive", "Backups"},
			FilenamePrefixes:   []string{"payroll_export", "payroll_adjustments", "payroll_sync", "salary_review_backup"},
			ExpectedTags:       []string{"pii", "business-data", "credentials"},
			ExpectedRuleThemes: []string{"payroll-filename-review", "database-connection-strings", "business-sensitive-review"},
			ExpectedSeverity:   "high",
			Render:             renderPayroll,
		},
		{
			Category:           "archive",
			Formats:            []string{"txt", "md", "csv", "docx", "xlsx"},
			Directories:        []string{"Archive", "Old", "Backups"},
			FilenamePrefixes:   []string{"legacy_customer_export_archive", "finance_backup_manifest", "old_admin_bundle", "retained_report_index"},
			ExpectedTags:       []string{"archives", "business-data"},
			ExpectedRuleThemes: []string{"backup-export-naming", "archive-review", "retention-review"},
			ExpectedSeverity:   "medium",
			Render:             renderArchive,
		},
		{
			Category:           "cloud",
			Formats:            []string{"json", "yaml", "yml", "env", "txt", "properties"},
			Directories:        []string{"Config", "Deploy", "Web", "IT/Admin"},
			FilenamePrefixes:   []string{"aws_credentials", "azure_service_principal", "kubeconfig", "cicd_runtime_secrets"},
			ExpectedTags:       []string{"cloud", "infrastructure"},
			ExpectedRuleThemes: []string{"cloud-config-exposure", "api-token-exposure", "cicd-secret-review"},
			ExpectedSeverity:   "high",
			Render:             renderCloud,
		},
		{
			Category:           "keys",
			Formats:            []string{"pem", "key", "crt", "pfx", "txt"},
			Directories:        []string{"IT/Admin", "Config", "VPN", "Archive"},
			FilenamePrefixes:   []string{"web_tls", "vpn_server_key", "id_rsa_backup", "legacy_cert_bundle"},
			ExpectedTags:       []string{"crypto", "credentials"},
			ExpectedRuleThemes: []string{"private-key-material", "certificate-material", "high-risk-extension-review"},
			ExpectedSeverity:   "critical",
			Render:             renderKeys,
		},
		{
			Category:           "logs",
			Formats:            []string{"log", "txt", "md", "csv"},
			Directories:        []string{"Temp", "Web", "Archive", "IT"},
			FilenamePrefixes:   []string{"auth_debug", "sync_error", "deployment_trace", "legacy_token_audit"},
			ExpectedTags:       []string{"logs", "credentials"},
			ExpectedRuleThemes: []string{"hardcoded-secret-indicators", "api-token-exposure", "log-review"},
			ExpectedSeverity:   "medium",
			Render:             renderLogs,
		},
		{
			Category:           "deployment",
			Formats:            []string{"xml", "json", "yaml", "ini", "conf"},
			Directories:        []string{"Deploy", "IT/Admin", "Archive", "Old"},
			FilenamePrefixes:   []string{"unattend", "answer_file", "release_manifest", "installer_response"},
			ExpectedTags:       []string{"deployment", "credentials"},
			ExpectedRuleThemes: []string{"unattended-install", "deployment-config-review", "hardcoded-secret-indicators"},
			ExpectedSeverity:   "high",
			Render:             renderDeployment,
		},
		{
			Category:           "vpn",
			Formats:            []string{"conf", "cfg", "txt", "md", "key"},
			Directories:        []string{"VPN", "IT/Admin", "Users/Bob"},
			FilenamePrefixes:   []string{"vpn_client", "remote_access", "prod_gateway", "vpn_support_bundle"},
			ExpectedTags:       []string{"vpn", "configuration", "credentials"},
			ExpectedRuleThemes: []string{"vpn-config-review", "private-key-material", "hardcoded-secret-indicators"},
			ExpectedSeverity:   "high",
			Render:             renderVPN,
		},
		{
			Category:           "keepass",
			Formats:            []string{"txt", "md", "cfg", "docx", "xlsx"},
			Directories:        []string{"Users/Alice", "Users/Bob", "IT"},
			FilenamePrefixes:   []string{"keepass_notes", "vault_reference", "passwords_export", "kdbx_inventory"},
			ExpectedTags:       []string{"password-manager"},
			ExpectedRuleThemes: []string{"keepass-filename-review", "password-manager-artifact-review"},
			ExpectedSeverity:   "medium",
			Render:             renderKeePass,
		},
		{
			Category:           "customer_export",
			Formats:            []string{"csv", "txt", "json", "xlsx", "md"},
			Directories:        []string{"Finance", "HR", "Archive", "Web"},
			FilenamePrefixes:   []string{"customer_export", "crm_dump", "support_contacts", "customer_contract_extract"},
			ExpectedTags:       []string{"pii", "business-data"},
			ExpectedRuleThemes: []string{"customer-export-review", "pii-sensitive-business-review", "export-filename-review"},
			ExpectedSeverity:   "medium",
			Render:             renderCustomerExport,
		},
	}
}

func renderConfig(ctx renderContext) []byte {
	switch ctx.Format {
	case "env":
		return text(
			"APP_USER=DEMO_APP_"+ctx.Token,
			"APP_PASSWORD=EXAMPLE_PASSWORD_"+ctx.Token,
			"APP_SECRET=NOT_A_REAL_SECRET_"+ctx.Token,
		)
	case "properties":
		return text(
			"service.user=DEMO_APP_"+ctx.Token,
			"service.password=EXAMPLE_PASSWORD_"+ctx.Token,
			"service.secret=NOT_A_REAL_SECRET_"+ctx.Token,
		)
	default:
		return text(
			"# Synthetic Snablr lab config",
			"username=DEMO_APP_"+ctx.Token,
			"password=EXAMPLE_PASSWORD_"+ctx.Token,
			"secret=NOT_A_REAL_SECRET_"+ctx.Token,
			"environment=lab",
		)
	}
}

func renderScript(ctx renderContext) []byte {
	switch ctx.Format {
	case "ps1":
		return text(
			"# Synthetic admin script",
			"$User = \"DEMO_ADMIN_"+ctx.Token+"\"",
			"$Password = \"EXAMPLE_PASSWORD_"+ctx.Token+"\"",
			"$ApiToken = \"FAKE_API_KEY_"+ctx.Token+"\"",
		)
	case "sh":
		return text(
			"# Synthetic shell script",
			"ADMIN_USER=DEMO_ADMIN_"+ctx.Token,
			"ADMIN_PASS=EXAMPLE_PASSWORD_"+ctx.Token,
			"API_TOKEN=FAKE_API_KEY_"+ctx.Token,
		)
	default:
		return text(
			"REM Synthetic script",
			"set ADMIN_USER=DEMO_ADMIN_"+ctx.Token,
			"set ADMIN_PASS=EXAMPLE_PASSWORD_"+ctx.Token,
			"set API_TOKEN=FAKE_API_KEY_"+ctx.Token,
		)
	}
}

func renderBackup(ctx renderContext) []byte {
	return text(
		"# Synthetic backup metadata",
		"BACKUP_OPERATOR=DEMO_BACKUP_"+ctx.Token,
		"BACKUP_PASSWORD=EXAMPLE_PASSWORD_"+ctx.Token,
		"ARCHIVE_PATH=SnablrLab/Archive/"+ctx.Filename,
		"NOTE=NOT_A_REAL_SECRET",
	)
}

func renderDatabase(ctx renderContext) []byte {
	switch ctx.Format {
	case "json":
		return mustJSON(map[string]string{
			"connectionString": "Server=sql-lab;Database=DemoDB;User Id=DEMO_SQL;Password=EXAMPLE_PASSWORD_" + ctx.Token,
			"dsn":              "DEMO_CONN_STRING_" + ctx.Token,
		})
	case "sql":
		return text(
			"-- Synthetic SQL connection sample",
			"CONNECT DEMO_SQL/EXAMPLE_PASSWORD_"+ctx.Token,
			"-- DEMO_CONN_STRING_"+ctx.Token,
		)
	default:
		return text(
			"db_user=DEMO_SQL_"+ctx.Token,
			"db_password=EXAMPLE_PASSWORD_"+ctx.Token,
			"dsn=DEMO_CONN_STRING_"+ctx.Token,
		)
	}
}

func renderWeb(ctx renderContext) []byte {
	switch ctx.Format {
	case "json":
		return mustJSON(map[string]string{
			"apiToken":       "FAKE_API_KEY_" + ctx.Token,
			"sessionSecret":  "NOT_A_REAL_SECRET_" + ctx.Token,
			"adminPassword":  "EXAMPLE_PASSWORD_" + ctx.Token,
			"runtimeProfile": "lab",
		})
	case "xml":
		return text(
			"<webConfig>",
			"  <apiToken>FAKE_API_KEY_"+ctx.Token+"</apiToken>",
			"  <sessionSecret>NOT_A_REAL_SECRET_"+ctx.Token+"</sessionSecret>",
			"  <adminPassword>EXAMPLE_PASSWORD_"+ctx.Token+"</adminPassword>",
			"</webConfig>",
		)
	default:
		return text(
			"api_token: FAKE_API_KEY_"+ctx.Token,
			"session_secret: NOT_A_REAL_SECRET_"+ctx.Token,
			"admin_password: EXAMPLE_PASSWORD_"+ctx.Token,
		)
	}
}

func renderHR(ctx renderContext) []byte {
	if ctx.Format == "csv" {
		return text(
			"employee_id,name,department,comment",
			"1001,Alice Example,HR,SYNTHETIC_RECORD_ONLY",
			"1002,Bob Example,PeopleOps,NOT_A_REAL_PERSON",
		)
	}
	return text(
		"Snablr lab HR placeholder document",
		"File: "+ctx.Filename,
		"Contains synthetic names only.",
	)
}

func renderFinance(ctx renderContext) []byte {
	if ctx.Format == "csv" {
		return text(
			"invoice_id,customer,amount,comment",
			"INV-1001,Example Corp,100.00,SYNTHETIC_ONLY",
			"INV-1002,Demo Holdings,250.00,NOT_A_REAL_FINANCE_RECORD",
		)
	}
	return text(
		"Snablr lab finance placeholder",
		"Budget password note: EXAMPLE_PASSWORD_"+ctx.Token,
		"Reference: FAKE_EXPORT_REFERENCE_"+ctx.Token,
	)
}

func renderPayroll(ctx renderContext) []byte {
	switch ctx.Format {
	case "csv":
		return text(
			"employee_id,pay_cycle,gross_pay,comment",
			"1001,2026-03,5000.00,SYNTHETIC_ONLY",
			"1002,2026-03,5500.00,NOT_A_REAL_PAYROLL_ROW",
		)
	case "xml":
		return text(
			"<payroll>",
			"  <syncUser>DEMO_PAYROLL_"+ctx.Token+"</syncUser>",
			"  <syncPassword>EXAMPLE_PASSWORD_"+ctx.Token+"</syncPassword>",
			"</payroll>",
		)
	default:
		return text(
			"payroll_user=DEMO_PAYROLL_"+ctx.Token,
			"payroll_password=EXAMPLE_PASSWORD_"+ctx.Token,
			"payroll_note=SYNTHETIC_ONLY",
		)
	}
}

func renderArchive(ctx renderContext) []byte {
	return text(
		"Snablr lab archive index",
		"archive_label="+ctx.Filename,
		"contains_export_reference=FAKE_EXPORT_REFERENCE_"+ctx.Token,
		"note=NOT_A_REAL_SECRET",
	)
}

func renderCloud(ctx renderContext) []byte {
	switch ctx.Format {
	case "json":
		return mustJSON(map[string]string{
			"aws_access_key_id":     "FAKE_API_KEY_" + ctx.Token,
			"aws_secret_access_key": "NOT_A_REAL_SECRET_" + ctx.Token,
			"azure_client_secret":   "EXAMPLE_PASSWORD_" + ctx.Token,
		})
	default:
		return text(
			"AWS_ACCESS_KEY_ID=FAKE_API_KEY_"+ctx.Token,
			"AWS_SECRET_ACCESS_KEY=NOT_A_REAL_SECRET_"+ctx.Token,
			"AZURE_CLIENT_SECRET=EXAMPLE_PASSWORD_"+ctx.Token,
			"KUBECONFIG=/tmp/NOT_REAL_KUBECONFIG_"+ctx.Token,
		)
	}
}

func renderKeys(ctx renderContext) []byte {
	switch ctx.Format {
	case "crt":
		return text(
			"-----BEGIN CERTIFICATE-----",
			"SNABLR_LAB_FAKE_CERTIFICATE_"+strings.ToUpper(strings.ReplaceAll(ctx.Token, "-", "_")),
			"-----END CERTIFICATE-----",
		)
	case "pfx":
		return text(
			"SNABLR LAB PLACEHOLDER PFX FILE",
			"NOT_A_REAL_CERTIFICATE_ARCHIVE_"+ctx.Token,
		)
	default:
		return text(
			"-----BEGIN PRIVATE KEY-----",
			"SNABLR_LAB_FAKE_KEY_"+strings.ToUpper(strings.ReplaceAll(ctx.Token, "-", "_")),
			"NOT_A_REAL_SECRET",
			"-----END PRIVATE KEY-----",
		)
	}
}

func renderLogs(ctx renderContext) []byte {
	return text(
		"[WARN] Synthetic credential-like log entry",
		"user=DEMO_LOG_"+ctx.Token,
		"password=EXAMPLE_PASSWORD_"+ctx.Token,
		"api_token=FAKE_API_KEY_"+ctx.Token,
		"note=NOT_A_REAL_SECRET",
	)
}

func renderDeployment(ctx renderContext) []byte {
	switch ctx.Format {
	case "xml":
		return text(
			"<deployment>",
			"  <Username>DEMO_DEPLOY_"+ctx.Token+"</Username>",
			"  <Password>EXAMPLE_PASSWORD_"+ctx.Token+"</Password>",
			"  <Token>FAKE_API_KEY_"+ctx.Token+"</Token>",
			"</deployment>",
		)
	case "json":
		return mustJSON(map[string]string{
			"adminUser":     "DEMO_DEPLOY_" + ctx.Token,
			"adminPassword": "EXAMPLE_PASSWORD_" + ctx.Token,
			"token":         "FAKE_API_KEY_" + ctx.Token,
		})
	default:
		return text(
			"admin_user=DEMO_DEPLOY_"+ctx.Token,
			"admin_password=EXAMPLE_PASSWORD_"+ctx.Token,
			"deployment_token=FAKE_API_KEY_"+ctx.Token,
		)
	}
}

func renderVPN(ctx renderContext) []byte {
	if ctx.Format == "key" {
		return renderKeys(ctx)
	}
	return text(
		"remote=vpn.lab.local",
		"username=DEMO_VPN_"+ctx.Token,
		"password=EXAMPLE_PASSWORD_"+ctx.Token,
		"shared_secret=NOT_A_REAL_SECRET_"+ctx.Token,
	)
}

func renderKeePass(ctx renderContext) []byte {
	return text(
		"Title: KeePass migration note",
		"VaultReference=VAULT_REF_"+ctx.Token,
		"MasterPasswordHint=EXAMPLE_PASSWORD_"+ctx.Token,
		"AttachmentRef=NOT_A_REAL_SECRET_"+ctx.Token,
	)
}

func renderCustomerExport(ctx renderContext) []byte {
	switch ctx.Format {
	case "csv":
		return text(
			"customer_id,company,region,comment",
			"C-1001,Example Corp,North,SYNTHETIC_ONLY",
			"C-1002,Demo Industries,South,NOT_A_REAL_CUSTOMER",
		)
	case "json":
		return mustJSON(map[string]any{
			"export": "customer_export",
			"rows": []map[string]string{
				{"customer_id": "C-1001", "company": "Example Corp", "comment": "SYNTHETIC_ONLY"},
				{"customer_id": "C-1002", "company": "Demo Industries", "comment": "NOT_A_REAL_CUSTOMER"},
			},
		})
	default:
		return text(
			"Snablr lab customer export placeholder",
			"export_reference=FAKE_EXPORT_REFERENCE_"+ctx.Token,
			"contains_no_real_customer_data=true",
		)
	}
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

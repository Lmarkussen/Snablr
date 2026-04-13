package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/config"
	"snablr/internal/diff"
	"snablr/internal/scanner"
	"snablr/internal/seed"
)

func sampleFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:          "content.synthetic_password",
		RuleName:        "Synthetic Password",
		Severity:        "high",
		Confidence:      "high",
		RuleConfidence:  "medium",
		ConfidenceScore: 78,
		ConfidenceReasons: []string{
			"content rule matched \"password = ReplaceMe123!\" for Detect a synthetic password assignment.",
			"path contains high-value keywords associated with sensitive or operational content",
			"multiple independent signal types increased confidence",
		},
		Category:    "credentials",
		TriageClass: "actionable",
		Actionable:  true,
		Correlated:  true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   78,
			FinalScore:                  78,
			ContentSignalStrength:       32,
			HeuristicSignalContribution: 18,
			ValueQualityScore:           14,
			ValueQualityLabel:           "high",
			ValueQualityReason:          "content includes non-placeholder secret-like or credential-like values",
			CorrelationContribution:     14,
			PathContextContribution:     14,
		},
		Priority:            95,
		PriorityReason:      "test priority reason",
		SharePriority:       90,
		SharePriorityReason: "high-value share",
		FilePath:            "Policies/Groups.xml",
		Share:               "SYSVOL",
		ShareDescription:    "Domain policies and scripts",
		ShareType:           "sysvol",
		Host:                "dc01",
		Source:              "dfs",
		DFSNamespacePath:    `\\example.local\dfs\policies`,
		DFSLinkPath:         "Policies/Groups.xml",
		SignalType:          "content",
		Match:               "password = ReplaceMe123!",
		MatchedText:         "password = ReplaceMe123!",
		MatchedTextRedacted: "password = ********",
		Snippet:             "user = alice\npassword = ReplaceMe123!\ndomain = example.local",
		Context:             "user = alice\npassword = ReplaceMe123!\ndomain = example.local",
		ContextRedacted:     "user = alice\npassword = ********\ndomain = example.local",
		PotentialAccount:    "user = alice",
		LineNumber:          12,
		MatchReason:         "file contents contained text that matches the rule.",
		RuleExplanation:     "This synthetic pattern simulates a hardcoded password assignment in a config-like file.",
		RuleRemediation:     "Move credentials into a managed secret store or environment-specific secret injection path.",
		FromSYSVOL:          true,
		MatchedRuleIDs:      []string{"content.synthetic_password", "filename.synthetic_env"},
		MatchedSignalTypes:  []string{"content", "filename", "path", "share_priority", "planner_priority"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "content", RuleID: "content.synthetic_password", RuleName: "Synthetic Password", Match: "password = ReplaceMe123!", Confidence: "medium", Weight: 32, Reason: "content rule matched \"password = ReplaceMe123!\" for Detect a synthetic password assignment."},
			{SignalType: "filename", RuleID: "filename.synthetic_env", RuleName: "Synthetic Env File", Match: "Groups.xml", Weight: 18, Reason: "filename rule matched \"Groups.xml\" for Detect a synthetic env file name."},
			{SignalType: "path", Weight: 12, Reason: "path suggests policy, preference, or script review material"},
			{SignalType: "share_priority", Weight: 12, Reason: "SYSVOL is treated as a high-value AD share"},
			{SignalType: "planner_priority", Weight: 12, Reason: "planner marked this file path as high-priority review material"},
		},
		Tags: []string{"credentials", "source:dfs", "ad-share:sysvol"},
	}
}

func sampleHeuristicFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "filename.password_export",
		RuleName:          "Password Export Filename",
		Severity:          "medium",
		Confidence:        "medium",
		RuleConfidence:    "medium",
		ConfidenceScore:   38,
		ConfidenceReasons: []string{"filename rule matched \"passwords\" for Detect credential-style exports.", "planner marked this path as relevant review material"},
		Category:          "credentials",
		TriageClass:       "weak-review",
		Actionable:        false,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   38,
			FinalScore:                  38,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 18,
			ValueQualityScore:           0,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from metadata and context rather than extracted value quality",
			CorrelationContribution:     8,
			PathContextContribution:     12,
		},
		Priority:            72,
		PriorityReason:      "test filename priority reason",
		SharePriority:       60,
		SharePriorityReason: "user profile share",
		FilePath:            "Users/Alice/Desktop/passwords.txt",
		Share:               "Users",
		ShareDescription:    "User profile home directories",
		ShareType:           "disk",
		Host:                "fs01",
		Source:              "cli",
		SignalType:          "filename",
		Match:               "passwords",
		MatchedText:         "passwords",
		MatchedTextRedacted: "passwords",
		MatchReason:         "filename matched a heuristic naming pattern covered by the rule.",
		RuleExplanation:     "This heuristic catches filenames that commonly indicate plaintext credential exports.",
		RuleRemediation:     "Review the file contents and remove plaintext secrets from shared locations.",
		MatchedRuleIDs:      []string{"filename.password_export"},
		MatchedSignalTypes:  []string{"filename", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.password_export", RuleName: "Password Export Filename", Match: "passwords", Confidence: "medium", Weight: 18, Reason: "filename rule matched \"passwords\" for Detect credential-style exports."},
			{SignalType: "path", Weight: 12, Reason: "path contains a desktop-style review location"},
		},
		Tags: []string{"credentials", "filenames", "review"},
	}
}

func sampleNTDSFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.secret_store_artifacts",
		RuleName:           "Secret Store Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Archive/Recovery/AD/NTDS.DIT",
		Share:              "Archive",
		Host:               "dc01",
		SignalType:         "filename",
		Match:              "NTDS.DIT",
		MatchedText:        "NTDS.DIT",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.secret_store_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.secret_store_artifacts", RuleName: "Secret Store Artifacts", Match: "NTDS.DIT", Confidence: "high", Weight: 18, Reason: "exact AD database artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store"},
	}
}

func sampleSystemHiveFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.windows_hive_artifacts",
		RuleName:           "Windows Hive Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Archive/Recovery/AD/SYSTEM",
		Share:              "Archive",
		Host:               "dc01",
		SignalType:         "filename",
		Match:              "SYSTEM",
		MatchedText:        "SYSTEM",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.windows_hive_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.windows_hive_artifacts", RuleName: "Windows Hive Artifacts", Match: "SYSTEM", Confidence: "high", Weight: 18, Reason: "exact SYSTEM hive artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store", "windows"},
	}
}

func samplePrivateKeyFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "keyinspect.content.private_key_header",
		RuleName:           "Validated Private Key Header",
		Severity:           "critical",
		Confidence:         "high",
		RuleConfidence:     "high",
		ConfidenceScore:    78,
		Category:           "crypto",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Users/Alice/.ssh/id_rsa",
		Share:              "Users",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "-----BEGIN OPENSSH PRIVATE KEY-----",
		MatchedText:        "-----BEGIN OPENSSH PRIVATE KEY-----",
		MatchReason:        "file contents contained text that matches the rule.",
		MatchedRuleIDs:     []string{"filename.private_key_artifacts", "keyinspect.content.private_key_header"},
		MatchedSignalTypes: []string{"filename", "validated"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.private_key_artifacts", RuleName: "Private Key Artifacts", Match: "id_rsa", Confidence: "high", Weight: 18, Reason: "exact private key artifact was identified"},
			{SignalType: "validated", RuleID: "keyinspect.content.private_key_header", RuleName: "Validated Private Key Header", Match: "-----BEGIN OPENSSH PRIVATE KEY-----", Confidence: "high", Weight: 28, Reason: "validated private key header was identified"},
		},
		Tags: []string{"crypto", "keys", "remote-access", "artifact:private-key", "validated:private-key-header"},
	}
}

func sampleClientAuthFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "extension.client_auth_artifacts",
		RuleName:           "Client Auth Artifact Extensions",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    52,
		Category:           "remote-access",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/.ssh/client-admin.ovpn",
		Share:              "Users",
		Host:               "fs01",
		SignalType:         "extension",
		Match:              ".ovpn",
		MatchedText:        ".ovpn",
		MatchReason:        "file extension matched an extension-based heuristic covered by the rule.",
		MatchedRuleIDs:     []string{"extension.client_auth_artifacts"},
		MatchedSignalTypes: []string{"extension"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "extension", RuleID: "extension.client_auth_artifacts", RuleName: "Client Auth Artifact Extensions", Match: ".ovpn", Confidence: "high", Weight: 18, Reason: "client-auth artifact extension was identified"},
		},
		Tags: []string{"remote-access", "vpn", "client-auth"},
	}
}

func samplePFXFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "extension.key_and_certificate_extensions",
		RuleName:           "Key And Certificate Extensions",
		Severity:           "high",
		Confidence:         "medium",
		RuleConfidence:     "medium",
		ConfidenceScore:    42,
		Category:           "crypto",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Recovery/Certificates/corp-admin.pfx",
		Share:              "Users",
		Host:               "fs01",
		SignalType:         "extension",
		Match:              ".pfx",
		MatchedText:        ".pfx",
		MatchReason:        "file extension matched an extension-based heuristic covered by the rule.",
		MatchedRuleIDs:     []string{"extension.key_and_certificate_extensions"},
		MatchedSignalTypes: []string{"extension"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "extension", RuleID: "extension.key_and_certificate_extensions", RuleName: "Key And Certificate Extensions", Match: ".pfx", Confidence: "medium", Weight: 18, Reason: "PKCS#12 certificate bundle extension was identified"},
		},
		Tags: []string{"crypto", "certificates", "extensions"},
	}
}

func sampleCertificatePasswordFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:              "content.password_assignment_indicators",
		RuleName:            "Password Assignment Indicators",
		Severity:            "high",
		Confidence:          "high",
		RuleConfidence:      "medium",
		ConfidenceScore:     72,
		Category:            "credentials",
		TriageClass:         "actionable",
		Actionable:          true,
		FilePath:            "Recovery/Certificates/certificate-passwords.txt",
		Share:               "Users",
		Host:                "fs01",
		SignalType:          "content",
		Match:               "password=CertImport!2026",
		MatchedText:         "password=CertImport!2026",
		MatchedTextRedacted: "password=********",
		Snippet:             "bundle=corp-admin.pfx\npassword=********",
		Context:             "bundle=corp-admin.pfx\npassword=CertImport!2026",
		ContextRedacted:     "bundle=corp-admin.pfx\npassword=********",
		LineNumber:          2,
		MatchReason:         "file contents contained text that matches the rule.",
		MatchedRuleIDs:      []string{"content.password_assignment_indicators"},
		MatchedSignalTypes:  []string{"content"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "content", RuleID: "content.password_assignment_indicators", RuleName: "Password Assignment Indicators", Match: "password=CertImport!2026", Confidence: "medium", Weight: 32, Reason: "content rule matched a nearby password assignment for the certificate bundle"},
		},
		Tags: []string{"credentials", "notes", "passwords"},
	}
}

func sampleWindowsCredentialsFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "wincredinspect.path.credentials",
		RuleName:           "Windows Credentials Store Path",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "windows-credentials",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/AppData/Roaming/Microsoft/Credentials/A1B2C3D4",
		Share:              "Profiles",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "/microsoft/credentials/",
		MatchedText:        "Users/Alice/AppData/Roaming/Microsoft/Credentials/A1B2C3D4",
		MatchReason:        "path matched an exact Windows credential-store location covered by the built-in artifact inspector.",
		MatchedRuleIDs:     []string{"wincredinspect.path.credentials"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "wincredinspect.path.credentials", RuleName: "Windows Credentials Store Path", Match: "/microsoft/credentials/", Confidence: "high", Weight: 40, Reason: "exact Windows Credentials store path was identified"},
			{SignalType: "path", Weight: 12, Reason: "path matched an exact Windows credential-store family under AppData/Microsoft"},
		},
		Tags: []string{"windows", "dpapi", "artifact:windows-credstore", "credstore:path-exact", "credstore:type:credentials"},
	}
}

func sampleAWSCredentialsFinding() scanner.Finding {
	accessKey := "AWSKEY-OPS-ALPHA-001"
	secretKey := "AWSSECRET-OPS-BRAVO-001"
	return scanner.Finding{
		RuleID:              "awsinspect.content.credentials_bundle",
		RuleName:            "AWS Credential Bundle",
		Severity:            "critical",
		Confidence:          "high",
		RuleConfidence:      "high",
		ConfidenceScore:     82,
		Category:            "credentials",
		TriageClass:         "actionable",
		Actionable:          true,
		FilePath:            "Users/Alice/.aws/credentials",
		Share:               "Users",
		Host:                "fs01",
		SignalType:          "validated",
		Match:               "aws_access_key_id + aws_secret_access_key",
		MatchedText:         "aws_access_key_id=" + accessKey + "\naws_secret_access_key=" + secretKey,
		MatchedTextRedacted: "aws_access_key_id=AWSK********\naws_secret_access_key=AWSS********",
		Snippet:             "aws_access_key_id=AWSK********",
		Context:             "aws_access_key_id=" + accessKey + "\naws_secret_access_key=" + secretKey,
		ContextRedacted:     "aws_access_key_id=AWSK********\naws_secret_access_key=AWSS********",
		MatchReason:         "file contents contained text that matches the rule.",
		MatchedRuleIDs:      []string{"awsinspect.path.credentials", "awsinspect.content.credentials_bundle"},
		MatchedSignalTypes:  []string{"validated", "content", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "awsinspect.content.credentials_bundle", RuleName: "AWS Credential Bundle", Match: "aws_access_key_id + aws_secret_access_key", Confidence: "high", Weight: 28, Reason: "validated AWS shared-credentials bundle was identified"},
		},
		Tags: []string{"aws", "cloud", "artifact:aws-credentials"},
	}
}

func sampleAWSConfigFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "awsinspect.path.config",
		RuleName:           "AWS Config Artifact",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "infrastructure",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/.aws/config",
		Share:              "Users",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              ".aws/config",
		MatchedText:        "Users/Alice/.aws/config",
		MatchReason:        "path matched an exact AWS shared-profile artifact.",
		MatchedRuleIDs:     []string{"awsinspect.path.config"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "awsinspect.path.config", RuleName: "AWS Config Artifact", Match: ".aws/config", Confidence: "high", Weight: 18, Reason: "exact AWS shared config artifact was identified"},
		},
		Tags: []string{"aws", "cloud", "artifact:aws-config"},
	}
}

func sampleDBConnectionFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:              "dbinspect.access.connection_string",
		RuleName:            "Validated Database Connection Details",
		Severity:            "high",
		Confidence:          "high",
		RuleConfidence:      "high",
		ConfidenceScore:     80,
		Category:            "database-access",
		TriageClass:         "actionable",
		Actionable:          true,
		FilePath:            "Apps/Payroll/.env",
		Share:               "Apps",
		Host:                "fs01",
		SignalType:          "validated",
		Match:               "postgresql -> db-prod.example.invalid -> payroll",
		MatchedText:         "postgresql://svc_payroll:Winter2025!@db-prod.example.invalid/payroll?sslmode=require",
		MatchedTextRedacted: "postgresql://svc_payroll:********@db-prod.example.invalid/payroll?sslmode=require",
		Context:             "postgresql://svc_payroll:Winter2025!@db-prod.example.invalid/payroll?sslmode=require",
		ContextRedacted:     "postgresql://svc_payroll:********@db-prod.example.invalid/payroll?sslmode=require",
		MatchReason:         "file contents contained text that matches the rule.",
		MatchedRuleIDs:      []string{"dbinspect.access.connection_string"},
		MatchedSignalTypes:  []string{"validated", "content"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "dbinspect.access.connection_string", RuleName: "Validated Database Connection Details", Match: "postgresql -> db-prod.example.invalid -> payroll", Confidence: "high", Weight: 28, Reason: "validated database connection details with authentication material were parsed from a connection string"},
		},
		Tags: []string{"database", "db:source:config", "db:type:config-credential"},
	}
}

func sampleWindowsProtectFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "wincredinspect.path.protect",
		RuleName:           "Windows DPAPI Protect Path",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "windows-credentials",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21/masterkey",
		Share:              "Profiles",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "/microsoft/protect/",
		MatchedText:        "Users/Alice/AppData/Roaming/Microsoft/Protect/S-1-5-21/masterkey",
		MatchReason:        "path matched an exact Windows credential-store location covered by the built-in artifact inspector.",
		MatchedRuleIDs:     []string{"wincredinspect.path.protect"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "wincredinspect.path.protect", RuleName: "Windows DPAPI Protect Path", Match: "/microsoft/protect/", Confidence: "high", Weight: 40, Reason: "exact Windows DPAPI Protect path was identified"},
			{SignalType: "path", Weight: 12, Reason: "path matched an exact Windows credential-store family under AppData/Microsoft"},
		},
		Tags: []string{"windows", "dpapi", "artifact:windows-credstore", "credstore:path-exact", "credstore:type:protect", "credstore:type:dpapi-protect"},
	}
}

func sampleFirefoxLoginsFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "browsercredinspect.firefox.logins",
		RuleName:           "Firefox Saved Logins Artifact",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "browser-credentials",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/logins.json",
		Share:              "Profiles",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "logins.json",
		MatchedText:        "users/alice/appdata/roaming/mozilla/firefox/profiles/abcd.default-release/logins.json",
		MatchReason:        "path matched an exact browser credential-store artifact covered by the built-in artifact inspector.",
		MatchedRuleIDs:     []string{"browsercredinspect.firefox.logins"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "browsercredinspect.firefox.logins", RuleName: "Firefox Saved Logins Artifact", Match: "logins.json", Confidence: "high", Weight: 40, Reason: "exact browser credential-store artifact was identified"},
			{SignalType: "path", Weight: 12, Reason: "path matched an exact browser profile credential-store family such as Firefox Profiles or Chromium User Data"},
		},
		Tags: []string{"browser", "firefox", "artifact:browser-credstore", "browsercred:type:firefox-logins"},
	}
}

func sampleFirefoxKey4Finding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "browsercredinspect.firefox.key4",
		RuleName:           "Firefox Key Store Artifact",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "browser-credentials",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Users/Alice/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release/key4.db",
		Share:              "Profiles",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "key4.db",
		MatchedText:        "users/alice/appdata/roaming/mozilla/firefox/profiles/abcd.default-release/key4.db",
		MatchReason:        "path matched an exact browser credential-store artifact covered by the built-in artifact inspector.",
		MatchedRuleIDs:     []string{"browsercredinspect.firefox.key4"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "browsercredinspect.firefox.key4", RuleName: "Firefox Key Store Artifact", Match: "key4.db", Confidence: "high", Weight: 40, Reason: "exact browser credential-store artifact was identified"},
			{SignalType: "path", Weight: 12, Reason: "path matched an exact browser profile credential-store family such as Firefox Profiles or Chromium User Data"},
		},
		Tags: []string{"browser", "firefox", "artifact:browser-credstore", "browsercred:type:firefox-key4"},
	}
}

func sampleBackupPathFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "backupinspect.path.windowsimagebackup",
		RuleName:           "WindowsImageBackup Exposure Path",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "high",
		ConfidenceScore:    34,
		Category:           "backup-exposure",
		TriageClass:        "weak-review",
		Actionable:         false,
		FilePath:           "Backups/SystemState/WindowsImageBackup/DC01/Backup 2025-01-01/C/Windows/System32/config/SAM",
		Share:              "Backups",
		Host:               "fs01",
		SignalType:         "validated",
		Match:              "/windowsimagebackup/",
		MatchedText:        "Backups/SystemState/WindowsImageBackup/DC01/Backup 2025-01-01/C/Windows/System32/config/SAM",
		MatchReason:        "path matched an exact backup or system-state storage family covered by the built-in artifact inspector.",
		MatchedRuleIDs:     []string{"backupinspect.path.windowsimagebackup"},
		MatchedSignalTypes: []string{"validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "backupinspect.path.windowsimagebackup", RuleName: "WindowsImageBackup Exposure Path", Match: "/windowsimagebackup/", Confidence: "high", Weight: 40, Reason: "exact WindowsImageBackup family was identified"},
			{SignalType: "path", Weight: 12, Reason: "path matched an exact backup or copied system-state family"},
		},
		Tags: []string{"backup", "windows", "artifact:backup-family", "backup-family:windowsimagebackup"},
	}
}

func sampleBackupNTDSFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.ad_database_backup_artifacts",
		RuleName:           "AD Database Backup Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Backups/SystemState/WindowsImageBackup/DC01/Backup 2025-01-01/C/Windows/System32/config/NTDS.DIT.bak",
		Share:              "Backups",
		Host:               "fs01",
		SignalType:         "filename",
		Match:              "NTDS.DIT.bak",
		MatchedText:        "NTDS.DIT.bak",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.ad_database_backup_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.ad_database_backup_artifacts", RuleName: "AD Database Backup Artifacts", Match: "NTDS.DIT.bak", Confidence: "high", Weight: 18, Reason: "exact AD database backup artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store", "active-directory"},
	}
}

func sampleBackupSystemFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.windows_hive_backup_artifacts",
		RuleName:           "Windows Hive Backup Artifacts",
		Severity:           "critical",
		Confidence:         "low",
		RuleConfidence:     "high",
		ConfidenceScore:    18,
		Category:           "credentials",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Backups/SystemState/WindowsImageBackup/DC01/Backup 2025-01-01/C/Windows/System32/config/SYSTEM.bak",
		Share:              "Backups",
		Host:               "fs01",
		SignalType:         "filename",
		Match:              "SYSTEM.bak",
		MatchedText:        "SYSTEM.bak",
		MatchReason:        "filename matched a heuristic naming pattern covered by the rule.",
		MatchedRuleIDs:     []string{"filename.windows_hive_backup_artifacts"},
		MatchedSignalTypes: []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.windows_hive_backup_artifacts", RuleName: "Windows Hive Backup Artifacts", Match: "SYSTEM.bak", Confidence: "high", Weight: 18, Reason: "exact SYSTEM hive backup artifact was identified"},
		},
		Tags: []string{"credentials", "secret-store", "windows"},
	}
}

func sampleConfigOnlyFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "filename.sensitive_config_names",
		RuleName:          "Sensitive Config Names",
		Severity:          "low",
		Confidence:        "low",
		RuleConfidence:    "high",
		ConfidenceScore:   24,
		ConfidenceReasons: []string{"configuration artifact was identified without actionable evidence"},
		Category:          "configuration",
		TriageClass:       "config-only",
		Actionable:        false,
		Correlated:        false,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   24,
			FinalScore:                  24,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 24,
			ValueQualityScore:           0,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from metadata and context rather than extracted value quality",
			CorrelationContribution:     0,
			PathContextContribution:     0,
		},
		Priority:            48,
		PriorityReason:      "config path",
		FilePath:            "Apps/appsettings.json",
		Share:               "Apps",
		ShareType:           "disk",
		Host:                "fs01",
		Source:              "file",
		SignalType:          "filename",
		Match:               "appsettings.json",
		MatchedText:         "appsettings.json",
		MatchedTextRedacted: "appsettings.json",
		MatchReason:         "filename matched a heuristic naming pattern covered by the rule.",
		RuleExplanation:     "Common configuration names often deserve review, but this alone is not actionable.",
		RuleRemediation:     "Review the file only if paired with stronger evidence such as embedded credentials or validated connection details.",
		MatchedRuleIDs:      []string{"filename.sensitive_config_names"},
		MatchedSignalTypes:  []string{"filename"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.sensitive_config_names", RuleName: "Sensitive Config Names", Match: "appsettings.json", Confidence: "high", Weight: 18, Reason: "filename rule matched \"appsettings.json\" for Detect common config filenames that frequently contain environment settings or embedded secrets."},
		},
		Tags: []string{"configuration", "filenames", "triage"},
	}
}

func sampleWeakScriptFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "extension.script_extensions",
		RuleName:          "Script Extensions",
		Severity:          "medium",
		Confidence:        "medium",
		RuleConfidence:    "medium",
		ConfidenceScore:   28,
		ConfidenceReasons: []string{"heuristic review signal did not include actionable evidence"},
		Category:          "scripts",
		TriageClass:       "weak-review",
		Actionable:        false,
		Correlated:        false,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   28,
			FinalScore:                  28,
			HeuristicSignalContribution: 28,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from script artifact presence without extracted credential evidence",
		},
		FilePath:           "IT/Scripts/deploy-users.ps1",
		Share:              "IT",
		ShareType:          "disk",
		Host:               "fs01",
		Source:             "cli",
		SignalType:         "extension",
		Match:              ".ps1",
		MatchedText:        ".ps1",
		MatchedRuleIDs:     []string{"extension.script_extensions"},
		MatchedSignalTypes: []string{"extension"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "extension", RuleID: "extension.script_extensions", RuleName: "Script Extensions", Match: ".ps1", Confidence: "medium", Weight: 18, Reason: "extension rule matched \".ps1\" for generic script review."},
		},
		Tags: []string{"scripts", "extensions", "triage"},
	}
}

func sampleSSHSupportFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "filename.ssh_supporting_artifacts",
		RuleName:           "SSH Supporting Artifacts",
		Severity:           "medium",
		Confidence:         "medium",
		RuleConfidence:     "medium",
		ConfidenceScore:    50,
		Category:           "remote-access",
		TriageClass:        "actionable",
		Actionable:         true,
		Correlated:         true,
		FilePath:           "IT/Admin/Keys/authorized_keys",
		Share:              "IT",
		ShareType:          "disk",
		Host:               "fs01",
		Source:             "cli",
		SignalType:         "filename",
		Match:              "authorized_keys",
		MatchedText:        "authorized_keys",
		MatchedRuleIDs:     []string{"filename.ssh_supporting_artifacts"},
		MatchedSignalTypes: []string{"filename", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "filename", RuleID: "filename.ssh_supporting_artifacts", RuleName: "SSH Supporting Artifacts", Match: "authorized_keys", Confidence: "medium", Weight: 18, Reason: "filename rule matched \"authorized_keys\" for SSH supporting context."},
		},
		Tags: []string{"artifact:ssh-support", "ssh", "remote-access"},
	}
}

func sampleBackupExtensionFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "extension.database_and_backup_extensions",
		RuleName:           "Database And Backup Extensions",
		Severity:           "high",
		Confidence:         "medium",
		RuleConfidence:     "medium",
		ConfidenceScore:    42,
		Category:           "archives",
		TriageClass:        "actionable",
		Actionable:         true,
		Correlated:         true,
		FilePath:           "Backups/SystemState/WindowsImageBackup/DC02/NTDS.DIT.bak",
		Share:              "Backups",
		ShareType:          "disk",
		Host:               "fs01",
		Source:             "cli",
		SignalType:         "extension",
		Match:              ".bak",
		MatchedText:        ".bak",
		MatchedRuleIDs:     []string{"extension.database_and_backup_extensions"},
		MatchedSignalTypes: []string{"extension", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "extension", RuleID: "extension.database_and_backup_extensions", RuleName: "Database And Backup Extensions", Match: ".bak", Confidence: "medium", Weight: 18, Reason: "extension rule matched \".bak\" for backup review."},
		},
		Tags: []string{"backups", "database", "extensions"},
	}
}

func sampleArchiveFinding() scanner.Finding {
	finding := sampleFinding()
	finding.FilePath = "Deploy/loot.zip!configs/web.config"
	finding.ArchivePath = "Deploy/loot.zip"
	finding.ArchiveMemberPath = "configs/web.config"
	finding.ArchiveLocalInspect = true
	return finding
}

func writeValidationManifest(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "seed-manifest.json")
	manifest := seed.Manifest{
		SeedPrefix: "SnablrLab",
		Entries: []seed.SeedManifestEntry{
			{
				Host:          "dc01",
				Share:         "SYSVOL",
				Path:          "Policies/Groups.xml",
				Category:      "database",
				ExpectedClass: "actionable",
			},
			{
				Host:          "fs01",
				Share:         "Apps",
				Path:          "Apps/appsettings.json",
				Category:      "database",
				ExpectedClass: "config-only",
			},
			{
				Host:          "fs01",
				Share:         "Deploy",
				Path:          "Deploy/app.env",
				Category:      "database",
				ExpectedClass: "weak-review",
			},
			{
				Host:          "fs01",
				Share:         "Deploy",
				Path:          "Deploy/appsettings.json",
				Category:      "database",
				ExpectedClass: "correlated-high-confidence",
			},
		},
	}
	if err := manifest.Write(path); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	return path
}

func TestJSONWriterGeneratesStructuredReport(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].DFSNamespacePath == "" || !report.Findings[0].FromSYSVOL {
		t.Fatalf("expected DFS and SYSVOL metadata, got %#v", report.Findings[0])
	}
	if report.Findings[0].ShareType != "sysvol" || report.Findings[0].ShareDescription != "Domain policies and scripts" {
		t.Fatalf("expected share metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].Confidence != "high" || report.Findings[0].RuleConfidence != "medium" || report.Findings[0].RuleExplanation == "" || report.Findings[0].RuleRemediation == "" {
		t.Fatalf("expected explainability metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].SignalType != "content" || report.Findings[0].MatchedTextRedacted == "" || report.Findings[0].LineNumber != 12 || report.Findings[0].ContextRedacted == "" || report.Findings[0].PotentialAccount != "user = alice" {
		t.Fatalf("expected signal-specific content metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].ConfidenceScore == 0 || len(report.Findings[0].MatchedRuleIDs) != 2 || len(report.Findings[0].SupportingSignals) == 0 {
		t.Fatalf("expected correlated signal metadata in JSON finding, got %#v", report.Findings[0])
	}
	if !report.Findings[0].Actionable || !report.Findings[0].Correlated || report.Findings[0].TriageClass != "actionable" {
		t.Fatalf("expected triage metadata in JSON finding, got %#v", report.Findings[0])
	}
	if report.Findings[0].ConfidenceBreakdown.BaseScore != 78 || report.Findings[0].ConfidenceBreakdown.ValueQualityScore == 0 || report.Findings[0].ConfidenceBreakdown.CorrelationContribution == 0 {
		t.Fatalf("expected confidence breakdown in JSON finding, got %#v", report.Findings[0].ConfidenceBreakdown)
	}
	if len(report.CategorySummaries) != 1 || report.CategorySummaries[0].Category != "credentials" {
		t.Fatalf("unexpected category summaries: %#v", report.CategorySummaries)
	}
	if report.Performance == nil || report.Performance.FilesScanned != 1 || report.Performance.FindingsTotal != 1 || report.Performance.DurationMS < 0 {
		t.Fatalf("expected performance summary in JSON report, got %#v", report.Performance)
	}
	if len(report.Performance.ClassificationDistribution) == 0 || report.Performance.ClassificationDistribution[0].Class != "actionable" {
		t.Fatalf("expected classification distribution in performance summary, got %#v", report.Performance)
	}
}

func sampleSQLiteFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:            "sqliteinspect.credentials.sensitive_value",
		RuleName:          "SQLite-Stored Sensitive Value",
		Severity:          "high",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   74,
		ConfidenceReasons: []string{"bounded SQLite inspection sampled an interesting table and column", "value quality checks indicate the value looks usable rather than placeholder data"},
		Category:          "credentials",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        false,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   74,
			FinalScore:                  74,
			ContentSignalStrength:       18,
			HeuristicSignalContribution: 10,
			ValueQualityScore:           18,
			ValueQualityLabel:           "high",
			ValueQualityReason:          "bounded SQLite inspection found a plausible non-placeholder secret",
			PathContextContribution:     8,
		},
		FilePath:           "Apps/payroll-cache.sqlite3::accounts.password",
		DatabaseFilePath:   "Apps/payroll-cache.sqlite3",
		DatabaseTable:      "accounts",
		DatabaseColumn:     "password",
		DatabaseRowContext: "username=svc_payroll",
		Share:              "Apps",
		ShareType:          "disk",
		Host:               "fs01",
		Source:             "smb",
		SignalType:         "validated",
		Match:              "Apps/payroll-cache.sqlite3::accounts.password",
		MatchedText:        "Synthet!cPass2025",
		Snippet:            "Apps/payroll-cache.sqlite3::accounts.password -> Synthet!cPass2025",
		Context:            "SQLite table: accounts\nColumn: password\nRow context: username=svc_payroll",
		MatchReason:        "bounded SQLite inspection found a strong secret-like value in an interesting table/column pair.",
		RuleExplanation:    "SQLite findings are promoted only for bounded samples from interesting tables and columns.",
		MatchedRuleIDs:     []string{"sqliteinspect.credentials.sensitive_value"},
		MatchedSignalTypes: []string{"validated"},
		SupportingSignals: []scanner.SupportingSignal{
			{SignalType: "validated", RuleID: "sqliteinspect.credentials.sensitive_value", RuleName: "SQLite-Stored Sensitive Value", Match: "accounts.password", Confidence: "high", Weight: 24, Reason: "bounded SQLite inspection found a strong secret-like value"},
		},
		Tags: []string{"database", "sqlite", "db:type:sqlite-row"},
	}
}

func sampleSQLiteSupportFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:             "dbinspect.access.dsn",
		RuleName:           "Validated Database DSN Credentials",
		Severity:           "high",
		Confidence:         "high",
		RuleConfidence:     "high",
		ConfidenceScore:    70,
		Category:           "database-access",
		TriageClass:        "actionable",
		Actionable:         true,
		FilePath:           "Apps/.env",
		Share:              "Apps",
		ShareType:          "disk",
		Host:               "fs01",
		Source:             "smb",
		SignalType:         "validated",
		Match:              "DB_CONNECTION",
		MatchedText:        "postgresql://svc_payroll:Synthet!cPass2025@sql01.lab.invalid/payroll",
		MatchedRuleIDs:     []string{"dbinspect.access.dsn"},
		MatchedSignalTypes: []string{"validated"},
		Tags:               []string{"database", "db:source:config"},
	}
}

func TestAugmentFindingsForReportingAddsADCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleNTDSFinding(),
		sampleSystemHiveFinding(),
	})

	if len(augmented) != 3 {
		t.Fatalf("expected raw findings plus one correlated AD finding, got %#v", augmented)
	}

	found := false
	for _, finding := range augmented {
		if finding.RuleID != adCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "active-directory" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated AD finding: %#v", finding)
		}
		if finding.FilePath != sampleNTDSFinding().FilePath || finding.Confidence != "high" {
			t.Fatalf("expected NTDS anchor and high confidence, got %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated AD finding in augmented results, got %#v", augmented)
	}
}

func TestJSONWriterIncludesADCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(sampleNTDSFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSystemHiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if report.Summary.MatchesFound != 3 || len(report.Findings) != 3 {
		t.Fatalf("expected augmented findings in summary and JSON output, got summary=%#v findings=%#v", report.Summary, report.Findings)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.RuleID != adCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "active-directory" || !finding.Correlated || finding.SignalType != "correlation" {
			t.Fatalf("unexpected correlated JSON finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated AD finding in JSON report, got %#v", report.Findings)
	}
}

func TestAugmentFindingsForReportingBuildsPrivateKeyCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		samplePrivateKeyFinding(),
		sampleClientAuthFinding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != privateKeyCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "remote-access" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated private key finding: %#v", finding)
		}
		if finding.FilePath != samplePrivateKeyFinding().FilePath || finding.Confidence != "high" {
			t.Fatalf("expected private key anchor and high confidence, got %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated private key finding in augmented results, got %#v", augmented)
	}
}

func TestJSONWriterIncludesPrivateKeyCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(samplePrivateKeyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleClientAuthFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	found := false
	for _, finding := range report.Findings {
		if finding.RuleID != privateKeyCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "remote-access" || !finding.Correlated || finding.SignalType != "correlation" {
			t.Fatalf("unexpected correlated JSON finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated private key finding in JSON report, got %#v", report.Findings)
	}
}

func TestAugmentFindingsForReportingBuildsWindowsCredentialStoreCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleWindowsCredentialsFinding(),
		sampleWindowsProtectFinding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != windowsCredCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "windows-credentials" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated windows credential-store finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated windows credential-store finding in augmented results, got %#v", augmented)
	}
}

func TestAugmentFindingsForReportingBuildsBrowserCredentialStoreCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleFirefoxLoginsFinding(),
		sampleFirefoxKey4Finding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != browserCredCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "browser-credentials" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated browser finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated browser credential-store finding in augmented results, got %#v", augmented)
	}
}

func TestAugmentFindingsForReportingBuildsAWSCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleAWSCredentialsFinding(),
		sampleAWSConfigFinding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != awsProfileCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "cloud" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated AWS finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated AWS finding in augmented results, got %#v", augmented)
	}
}

func TestAugmentFindingsForReportingBuildsCertificateBundleCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		samplePFXFinding(),
		sampleCertificatePasswordFinding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != certificateBundleCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "remote-access" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated certificate finding: %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated certificate bundle finding in augmented results, got %#v", augmented)
	}
}

func TestAugmentFindingsForReportingBuildsBackupCorrelation(t *testing.T) {
	t.Parallel()

	augmented := augmentFindingsForReporting([]scanner.Finding{
		sampleBackupNTDSFinding(),
		sampleBackupSystemFinding(),
		sampleBackupPathFinding(),
	})

	found := false
	for _, finding := range augmented {
		if finding.RuleID != backupCorrelationRuleID {
			continue
		}
		found = true
		if finding.Category != "backup-exposure" || !finding.Correlated || !finding.Actionable {
			t.Fatalf("unexpected correlated backup finding: %#v", finding)
		}
		if finding.FilePath != sampleBackupNTDSFinding().FilePath || finding.Confidence != "high" {
			t.Fatalf("expected NTDS anchor and high confidence, got %#v", finding)
		}
	}
	if !found {
		t.Fatalf("expected correlated backup finding in augmented results, got %#v", augmented)
	}
}

func TestJSONWriterIncludesAccessPathSummaries(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	for _, finding := range []scanner.Finding{
		sampleBackupNTDSFinding(),
		sampleBackupSystemFinding(),
		sampleBackupPathFinding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if len(report.AccessPaths) == 0 {
		t.Fatalf("expected access path summaries in JSON report, got %#v", report)
	}
	found := false
	for _, item := range report.AccessPaths {
		if item.RuleID != backupCorrelationRuleID {
			continue
		}
		found = true
		if item.Label != "System-state backup exposure" || item.PrimaryPath == "" {
			t.Fatalf("unexpected backup access path summary: %#v", item)
		}
		if item.PriorityTier != "high" || item.ExploitabilityScore < 90 || item.Rank <= 0 {
			t.Fatalf("expected ranked high-priority backup access path summary, got %#v", item)
		}
		if len(item.RelatedArtifacts) == 0 {
			t.Fatalf("expected related artifacts in access path summary, got %#v", item)
		}
	}
	if !found {
		t.Fatalf("expected backup access path summary in JSON report, got %#v", report.AccessPaths)
	}
}

func TestJSONWriterIncludesBrowserAccessPathSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	for _, finding := range []scanner.Finding{
		sampleFirefoxLoginsFinding(),
		sampleFirefoxKey4Finding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	found := false
	for _, item := range report.AccessPaths {
		if item.RuleID != browserCredCorrelationRuleID {
			continue
		}
		found = true
		if item.Label != "Browser credential-store exposure" || item.PrimaryPath == "" {
			t.Fatalf("unexpected browser access path summary: %#v", item)
		}
		if item.PriorityTier != "medium" || item.ExploitabilityScore <= 0 || item.Rank <= 0 {
			t.Fatalf("expected ranked browser access path summary, got %#v", item)
		}
	}
	if !found {
		t.Fatalf("expected browser access path summary in JSON report, got %#v", report.AccessPaths)
	}
}

func TestJSONWriterIncludesAWSAccessPathSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	for _, finding := range []scanner.Finding{
		sampleAWSCredentialsFinding(),
		sampleAWSConfigFinding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	found := false
	for _, item := range report.AccessPaths {
		if item.RuleID != awsProfileCorrelationRuleID {
			continue
		}
		found = true
		if item.Label != "AWS credential profile" || item.PrimaryPath == "" {
			t.Fatalf("unexpected AWS access path summary: %#v", item)
		}
		if item.PriorityTier != "high" || item.ExploitabilityScore <= 0 || item.Rank <= 0 {
			t.Fatalf("expected ranked AWS access path summary, got %#v", item)
		}
	}
	if !found {
		t.Fatalf("expected AWS access path summary in JSON report, got %#v", report.AccessPaths)
	}
}

func TestJSONWriterIncludesCertificateBundleAccessPathSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	for _, finding := range []scanner.Finding{
		samplePFXFinding(),
		sampleCertificatePasswordFinding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	found := false
	for _, item := range report.AccessPaths {
		if item.RuleID != certificateBundleCorrelationRuleID {
			continue
		}
		found = true
		if item.Label != "Certificate/client-auth bundle" || item.PrimaryPath == "" {
			t.Fatalf("unexpected certificate access path summary: %#v", item)
		}
		if item.PriorityTier != "high" || item.ExploitabilityScore <= 0 || item.Rank <= 0 {
			t.Fatalf("expected ranked certificate access path summary, got %#v", item)
		}
	}
	if !found {
		t.Fatalf("expected certificate access path summary in JSON report, got %#v", report.AccessPaths)
	}
}

func TestCredsWriterExportsCuratedHighConfidenceCredentials(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})

	findings := []scanner.Finding{
		sampleAWSCredentialsFinding(),
		sampleDBConnectionFinding(),
		samplePrivateKeyFinding(),
		sampleHeuristicFinding(),
		sampleAWSConfigFinding(),
		{
			RuleID:              "content.password_assignment_indicators",
			RuleName:            "Password Assignment Indicators",
			Severity:            "high",
			Confidence:          "high",
			RuleConfidence:      "high",
			ConfidenceScore:     80,
			Category:            "credentials",
			TriageClass:         "actionable",
			Actionable:          true,
			FilePath:            "Notes/passwords.txt",
			Share:               "Docs",
			Host:                "fs01",
			SignalType:          "content",
			Match:               "password=EXAMPLE_PASSWORD_001",
			MatchedText:         "password=EXAMPLE_PASSWORD_001",
			MatchedTextRedacted: "password=********",
			Context:             "password=EXAMPLE_PASSWORD_001",
			ContextRedacted:     "password=********",
			MatchedRuleIDs:      []string{"content.password_assignment_indicators"},
			MatchedSignalTypes:  []string{"content"},
		},
	}
	for _, finding := range findings {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"==== AWS Credentials ====",
		"==== Database Credentials ====",
		"==== SSH Private Keys ====",
		`Path: \\fs01\Users\Users\Alice\.aws\credentials`,
		"AccessKey: AWSKEY-OPS-ALPHA-001",
		"SecretKey: AWSSECRET-OPS-BRAVO-001",
		`Path: \\fs01\Apps\Apps\Payroll\.env`,
		"Host: db-prod.example.invalid",
		"Database: payroll",
		"User: svc_payroll",
		"Password: Winter2025!",
		`Path: \\fs01\Users\Users\Alice\.ssh\id_rsa`,
		"Type: -----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected creds export to contain %q, got:\n%s", want, output)
		}
	}
	for _, dontWant := range []string{
		"Password Export Filename",
		"EXAMPLE_PASSWORD_001",
		"==== infrastructure ====",
	} {
		if strings.Contains(output, dontWant) {
			t.Fatalf("did not expect creds export to contain %q, got:\n%s", dontWant, output)
		}
	}
}

func TestCredsWriterFormatsBundleContextWithoutInventingUser(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})

	if err := writer.WriteFinding(sampleCertificatePasswordFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"==== Application / Deployment Credentials ====",
		`Path: \\fs01\Users\Recovery\Certificates\certificate-passwords.txt`,
		"Bundle: corp-admin.pfx",
		"Password: CertImport!2026",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected creds export to contain %q, got:\n%s", want, output)
		}
	}
	if strings.Contains(output, "User: bundle") {
		t.Fatalf("did not expect invented user label for bundle context, got:\n%s", output)
	}
}

func TestCredsWriterDeduplicatesCredentialEntriesAcrossPaths(t *testing.T) {
	var buf bytes.Buffer
	writer := NewCredsWriter(&buf, nopCloser{})

	first := sampleAWSCredentialsFinding()
	second := sampleAWSCredentialsFinding()
	second.FilePath = "Users/Bob/.aws/credentials"
	second.Host = "fs02"
	second.Share = "Profiles"

	for _, finding := range []scanner.Finding{first, second} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	output := buf.String()
	if strings.Count(output, "==== AWS Credentials ====") != 1 {
		t.Fatalf("expected one AWS group, got:\n%s", output)
	}
	if strings.Count(output, "AccessKey: AWSKEY-OPS-ALPHA-001") != 1 {
		t.Fatalf("expected deduplicated AWS entry, got:\n%s", output)
	}
	for _, want := range []string{
		`- \\fs01\Users\Users\Alice\.aws\credentials`,
		`- \\fs02\Profiles\Users\Bob\.aws\credentials`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected deduplicated creds export to contain %q, got:\n%s", want, output)
		}
	}
}

func TestSuppressionWriterSuppressesConfiguredFindingsAndReportsSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := NewJSONWriter(&buf, nil, true)
	sink := WrapWithSuppression(base, config.SuppressionConfig{
		SampleLimit: 5,
		Rules: []config.SuppressionRule{
			{
				ID:           "suppress-synthetic-password",
				Reason:       "known benign synthetic example",
				Enabled:      true,
				RuleIDs:      []string{"content.synthetic_password"},
				PathPrefixes: []string{"Policies/"},
			},
		},
	})
	SetScanProfile(sink, "default")

	if err := sink.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := sink.WriteFinding(sampleHeuristicFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Profile != "default" {
		t.Fatalf("expected profile to be recorded, got %#v", report.Profile)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != sampleHeuristicFinding().RuleID {
		t.Fatalf("expected suppressed finding to be omitted from visible findings, got %#v", report.Findings)
	}
	if report.Suppression == nil || report.Suppression.TotalSuppressed != 1 {
		t.Fatalf("expected suppression summary, got %#v", report.Suppression)
	}
	if len(report.Suppression.Rules) != 1 || report.Suppression.Rules[0].ID != "suppress-synthetic-password" {
		t.Fatalf("expected suppression rule summary, got %#v", report.Suppression)
	}
	if len(report.Suppression.Samples) != 1 || report.Suppression.Samples[0].FilePath != sampleFinding().FilePath {
		t.Fatalf("expected suppression sample for hidden finding, got %#v", report.Suppression)
	}
}

func TestHTMLWriterRendersSuppressionSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	sink := WrapWithSuppression(base, config.SuppressionConfig{
		SampleLimit: 5,
		Rules: []config.SuppressionRule{
			{
				ID:         "suppress-heuristic-password-export",
				Reason:     "known benign export naming",
				Enabled:    true,
				ExactPaths: []string{"Users/Alice/Desktop/passwords.txt"},
				RuleIDs:    []string{"filename.password_export"},
				Shares:     []string{"Users"},
				Hosts:      []string{"fs01"},
			},
		},
	})
	SetScanProfile(sink, "validation")
	if err := sink.WriteFinding(sampleHeuristicFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := sink.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Profile", "validation", "Suppressed Findings", "suppress-heuristic-password-export", "known benign export naming", "Users/Alice/Desktop/passwords.txt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
	if strings.Contains(out, "Password Export Filename") {
		t.Fatalf("expected suppressed finding to be omitted from visible html findings, got %s", out)
	}
}

func TestAccessPathSummariesRankByExploitability(t *testing.T) {
	t.Parallel()

	summaries := buildAccessPathSummaries(augmentFindingsForReporting([]scanner.Finding{
		sampleFirefoxLoginsFinding(),
		sampleFirefoxKey4Finding(),
		sampleBackupNTDSFinding(),
		sampleBackupSystemFinding(),
		sampleBackupPathFinding(),
		sampleNTDSFinding(),
		sampleSystemHiveFinding(),
	}))

	if len(summaries) < 3 {
		t.Fatalf("expected multiple ranked access path summaries, got %#v", summaries)
	}
	if summaries[0].Type != "ad-compromise-path" || summaries[0].PriorityTier != "high" {
		t.Fatalf("expected AD compromise path to rank first, got %#v", summaries[0])
	}
	backupIndex := -1
	browserIndex := -1
	for i, item := range summaries {
		switch item.Type {
		case "backup-exposure-path":
			if backupIndex == -1 {
				backupIndex = i
			}
		case "browser-credential-store-exposure":
			if browserIndex == -1 {
				browserIndex = i
			}
		}
	}
	if backupIndex == -1 || browserIndex == -1 {
		t.Fatalf("expected backup and browser access path summaries, got %#v", summaries)
	}
	if backupIndex >= browserIndex {
		t.Fatalf("expected backup exposure path to rank above browser exposure, got backup=%d browser=%d summaries=%#v", backupIndex, browserIndex, summaries)
	}
	if summaries[backupIndex].ExploitabilityScore <= summaries[browserIndex].ExploitabilityScore {
		t.Fatalf("expected backup exposure score to exceed browser exposure score, got backup=%#v browser=%#v", summaries[backupIndex], summaries[browserIndex])
	}
	for i, item := range summaries {
		if item.Rank != i+1 {
			t.Fatalf("expected rank %d for item %#v", i+1, item)
		}
	}
}

func TestJSONWriterIncludesDiffSummaryWhenBaselineIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetBaselineFindings([]scanner.Finding{
		{
			RuleID:         "content.synthetic_password",
			RuleName:       "Synthetic Password",
			Severity:       "medium",
			Category:       "credentials",
			FilePath:       "Policies/Groups.xml",
			Share:          "SYSVOL",
			Host:           "dc01",
			Match:          "password = ReplaceMe123!",
			MatchedRuleIDs: []string{"content.synthetic_password", "filename.synthetic_env"},
		},
		{
			RuleID:   "content.old_only",
			RuleName: "Old Only",
			Severity: "low",
			Category: "credentials",
			FilePath: "Policies/Old.xml",
			Share:    "SYSVOL",
			Host:     "dc01",
			Match:    "old",
		},
	})
	writer.SetBaselinePerformance(&diff.PerformanceSummary{
		FilesScanned:   10,
		FindingsTotal:  2,
		DurationMS:     500,
		FilesPerSecond: 20,
		ClassificationDistribution: []diff.ClassificationSummary{
			{Class: "actionable", Count: 2},
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.DiffSummary == nil {
		t.Fatalf("expected diff summary in report")
	}
	if report.DiffSummary.Changed != 1 || report.DiffSummary.Removed != 1 {
		t.Fatalf("unexpected diff summary: %#v", report.DiffSummary)
	}
	if report.Findings[0].DiffStatus != string(diff.StatusChanged) {
		t.Fatalf("expected changed diff status, got %#v", report.Findings[0])
	}
	if len(report.Findings[0].ChangedFields) == 0 {
		t.Fatalf("expected changed fields metadata, got %#v", report.Findings[0])
	}
	if report.PerformanceComparison == nil || report.PerformanceComparison.FindingsDelta != -1 {
		t.Fatalf("expected performance comparison in report, got %#v", report.PerformanceComparison)
	}
}

func TestJSONWriterIncludesValidationSummaryWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.Validation == nil || !report.Validation.HasValidation {
		t.Fatalf("expected validation summary, got %#v", report.Validation)
	}
	if report.Validation.ExpectedItems != 4 || report.Validation.FoundItems != 2 || report.Validation.MissedItems != 2 {
		t.Fatalf("unexpected validation summary: %#v", report.Validation)
	}
	if len(report.Validation.ClassCoverage) == 0 || len(report.Validation.MissedExpected) != 2 {
		t.Fatalf("expected class coverage and missed expected items, got %#v", report.Validation)
	}
}

func TestJSONWriterIncludesValidationModeSummaryWhenEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	writer.SetValidationMode(true)
	writer.RecordSkip(scanner.FileMetadata{FilePath: "skip.txt"}, "max size")
	writer.RecordSuppressedFinding(scanner.SuppressedFinding{FilePath: "suppressed.env", RuleID: "content.password_assignment_indicators"})
	writer.RecordVisibleFinding(sampleFinding())
	writer.RecordVisibleFinding(sampleConfigOnlyFinding())
	writer.RecordDowngradedFinding(sampleConfigOnlyFinding())
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if report.ValidationMode == nil || !report.ValidationMode.Enabled {
		t.Fatalf("expected validation mode summary, got %#v", report.ValidationMode)
	}
	if report.ValidationMode.SuppressedFindings != 1 || report.ValidationMode.VisibleFindings != 2 || report.ValidationMode.DowngradedFindings != 1 {
		t.Fatalf("unexpected validation mode counts: %#v", report.ValidationMode)
	}
}

func TestJSONWriterIncludesArchiveMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(sampleArchiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", report.Findings)
	}
	finding := report.Findings[0]
	if finding.ArchivePath != "Deploy/loot.zip" || finding.ArchiveMemberPath != "configs/web.config" || !finding.ArchiveLocalInspect {
		t.Fatalf("expected archive metadata in JSON output, got %#v", finding)
	}
}

func TestConsoleWriterIncludesContextMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Share Type: sysvol", "Share Description: Domain policies and scripts", "Source: dfs", "AD Share: SYSVOL", "DFS Namespace:", "Confidence: HIGH (78)", "Matched Rules:", "Signals:", "Signal: content", "Line: 12", "Potential account context: user = alice", "Matched text: password = ReplaceMe123!", "Context:", "domain = example.local", "Confidence Raised By:", "Rule Note:", "Remediation:", "Performance: files_scanned=0 findings=1", "Classification Distribution: actionable=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesPerformanceComparisonWhenBaselineIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetBaselinePerformance(&diff.PerformanceSummary{
		FilesScanned:   5,
		FindingsTotal:  2,
		DurationMS:     250,
		FilesPerSecond: 20,
		ClassificationDistribution: []diff.ClassificationSummary{
			{Class: "actionable", Count: 2},
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Performance Comparison:", "Classification Changes:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesValidationSummaryWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Validation: expected=4 found=2 missed=2", "Validation Classes:", "informational:", "actionable:", "Validation Missed:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestConsoleWriterIncludesValidationModeSummaryWhenEnabled(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	writer.SetValidationMode(true)
	writer.RecordSkip(scanner.FileMetadata{FilePath: "skip.txt"}, "max size")
	writer.RecordSuppressedFinding(scanner.SuppressedFinding{FilePath: "suppressed.env", RuleID: "content.password_assignment_indicators"})
	writer.RecordVisibleFinding(sampleFinding())
	writer.RecordVisibleFinding(sampleConfigOnlyFinding())
	writer.RecordDowngradedFinding(sampleConfigOnlyFinding())
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Validation Mode: total=3 suppressed=1 visible=2 downgraded=1", "high_confidence=1", "skipped_files=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got %s", want, out)
		}
	}
}

func TestHTMLWriterRendersStandaloneTriageReport(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleHeuristicFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Snablr Scan Report", "Version", "quickFilter", "severityFilter", "categoryFilter", "confidenceFilter", "sourceFilter", "signalFilter", "scopeFilter", "correlatedOnly", "hideConfigOnly", "hideLowConfidence", "hideNonActionable", "resetFilters", "filterStatus", "Severity Summary", "Category Summary", "Host Summary", "SYSVOL", "Signal Type", "Visible Evidence", "password = ReplaceMe123!", "user = alice", "Line Number", "Rule Explanation", "confidence high", "Supporting Signals", "Confidence Breakdown", "Content signal strength", "Value quality:", "Final score:", "Remediation", "Download", "Supporting Context", "Supporting Findings", "Password Export Filename", "filename matched a heuristic naming pattern covered by the rule."} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
	for _, want := range []string{"details.finding-group, details.supporting-group", ".finding-card, .supporting-card", "class=\"group supporting-group\"", "class=\"supporting-card\"\n              data-search=", "data-triage=\"config-only\"", "data-actionable=\"false\""} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
	for _, want := range []string{"id=\"hideConfigOnly\" type=\"checkbox\" checked", "id=\"hideNonActionable\" type=\"checkbox\" checked"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to enable default low-noise filters, missing %q", want)
		}
	}
	for _, want := range []string{"Show Evidence", "Raw Supporting Signals"} {
		if strings.Contains(out, want) {
			t.Fatalf("expected html output not to contain %q", want)
		}
	}
	for _, want := range []string{"Heuristic file hit", "Config artifact only."} {
		if strings.Contains(out, want) {
			t.Fatalf("expected html output not to render supporting-only items as primary cards, found %q", want)
		}
	}
}

func TestHTMLWriterBoundsLargeDatabaseEvidence(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}

	finding := sampleDBConnectionFinding()
	large := "SELECT secret FROM payroll_users WHERE password='Winter2025!'; " + strings.Repeat("UNION SELECT token FROM audit_log; ", 80)
	finding.MatchedText = large
	finding.Context = large
	finding.ContextRedacted = large
	finding.Snippet = large

	if err := writer.WriteFinding(finding); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[truncated]") {
		t.Fatalf("expected html output to mark truncated oversized DB evidence, got:\n%s", out)
	}
	if strings.Count(out, "UNION SELECT token FROM audit_log;") > 20 {
		t.Fatalf("expected bounded DB evidence and search text, got excessive repeated SQL in report")
	}
}

func TestAugmentFindingsForReportingDeduplicatesSameFileSameEvidence(t *testing.T) {
	t.Parallel()

	first := sampleFinding()
	second := sampleFinding()
	second.ConfidenceScore = first.ConfidenceScore - 10

	augmented := augmentFindingsForReporting([]scanner.Finding{first, second})
	count := 0
	for _, finding := range augmented {
		if finding.RuleID == first.RuleID && finding.FilePath == first.FilePath {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected duplicate same-file same-evidence findings to collapse, got %#v", augmented)
	}
}

func TestHTMLWriterShowsDiffSummaryAndHighlights(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.SetBaselineFindings([]scanner.Finding{
		{
			RuleID:         sampleFinding().RuleID,
			RuleName:       sampleFinding().RuleName,
			Severity:       "medium",
			Category:       sampleFinding().Category,
			FilePath:       sampleFinding().FilePath,
			Share:          sampleFinding().Share,
			Host:           sampleFinding().Host,
			Match:          sampleFinding().Match,
			MatchedRuleIDs: append([]string{}, sampleFinding().MatchedRuleIDs...),
		},
	})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Baseline Diff", "Changed Since Baseline", "badge diff-changed", "status-changed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterIncludesValidationSectionWhenManifestIsSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	writer.SetValidationManifest(writeValidationManifest(t))
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleConfigOnlyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Seeded Validation", "Config Suppressed", "Actionable Promoted", "Over-Promoted Items", "Missed Expected Items", "correlated / high-confidence"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersADCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleNTDSFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSystemHiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"correlation.ad.ntds_system", "signal correlation", "NTDS.DIT and SYSTEM artifacts were found together in the same directory context"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersPrivateKeyCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(samplePrivateKeyFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleClientAuthFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"correlation.remote_access.private_key_bundle", "Private Key Exposure Path", "client-admin.ovpn", "id_rsa"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersWindowsCredentialStoreCorrelationFinding(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleWindowsCredentialsFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleWindowsProtectFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"correlation.windows.dpapi_credential_store", "Windows DPAPI Credential Store Exposure Path", "windows-credentials"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestHTMLWriterRendersBrowserAccessPathSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleFirefoxLoginsFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleFirefoxKey4Finding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, dontWant := range []string{"Top Access Paths", "access-path-grid", "access-path-card", "access-path-primary-value"} {
		if strings.Contains(out, dontWant) {
			t.Fatalf("did not expect html output to contain %q", dontWant)
		}
	}
	for _, want := range []string{"logins.json", "key4.db"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to retain finding detail content %q", want)
		}
	}
}

func TestHTMLWriterRendersBackupAccessPathSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	for _, finding := range []scanner.Finding{
		sampleBackupNTDSFinding(),
		sampleBackupSystemFinding(),
		sampleBackupPathFinding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "Top Access Paths") {
		t.Fatalf("did not expect html output to contain Top Access Paths")
	}
	if !strings.Contains(out, "WindowsImageBackup") || !strings.Contains(out, "NTDS.DIT") {
		t.Fatalf("expected html output to retain finding detail content")
	}
}

func TestHTMLWriterRendersArchiveMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleArchiveFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Deploy/loot.zip!configs/web.config", "Archive Member", "configs/web.config", "Archive Inspection", "local", "Download", "href=\"file://dc01/SYSVOL/Deploy/loot.zip\""} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestNewWriterNoTUIForcesPlainConsole(t *testing.T) {
	sink, err := NewWriter(config.OutputConfig{
		Format: "console",
		NoTUI:  true,
	})
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	defer sink.Close()

	if _, ok := sink.(*ConsoleWriter); !ok {
		t.Fatalf("expected plain ConsoleWriter when no_tui is enabled, got %T", sink)
	}
}

func TestDetermineLiveSinkModeDefaultsToTUIForInteractiveHTML(t *testing.T) {
	if got := determineLiveSinkMode("html", false, true); got != liveSinkTUI {
		t.Fatalf("expected interactive html runs to use TUI, got %q", got)
	}
}

func TestDetermineLiveSinkModeDefaultsToTUIForInteractiveAll(t *testing.T) {
	if got := determineLiveSinkMode("all", false, true); got != liveSinkTUI {
		t.Fatalf("expected interactive all runs to use TUI, got %q", got)
	}
}

func TestDetermineLiveSinkModeDefaultsToTUIForInteractiveCombinedExports(t *testing.T) {
	if got := determineLiveSinkMode("html,json", false, true); got != liveSinkTUI {
		t.Fatalf("expected interactive html,json runs to use TUI, got %q", got)
	}
}

func TestDetermineLiveSinkModeNoTUIDisablesTUIExplicitly(t *testing.T) {
	if got := determineLiveSinkMode("html", true, true); got != liveSinkConsole {
		t.Fatalf("expected --no-tui html runs to use plain console, got %q", got)
	}
}

func TestDetermineLiveSinkModeNonInteractiveHTMLIsExportOnly(t *testing.T) {
	if got := determineLiveSinkMode("html", false, false); got != liveSinkNone {
		t.Fatalf("expected non-interactive html runs without --no-tui to avoid live sink, got %q", got)
	}
}

func TestNewWriterNoTUIHTMLIncludesConsoleAndHTML(t *testing.T) {
	tmpDir := t.TempDir()
	sink, err := NewWriter(config.OutputConfig{
		Format:  "html",
		NoTUI:   true,
		HTMLOut: filepath.Join(tmpDir, "report.html"),
	})
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	defer sink.Close()

	multi, ok := sink.(*MultiWriter)
	if !ok {
		t.Fatalf("expected MultiWriter for html + no_tui, got %T", sink)
	}
	if len(multi.sinks) != 2 {
		t.Fatalf("expected 2 sinks for html + no_tui, got %d", len(multi.sinks))
	}
	if _, ok := multi.sinks[0].(*ConsoleWriter); !ok {
		t.Fatalf("expected first sink to be ConsoleWriter, got %T", multi.sinks[0])
	}
	if _, ok := multi.sinks[1].(*HTMLWriter); !ok {
		t.Fatalf("expected second sink to be HTMLWriter, got %T", multi.sinks[1])
	}
}

func TestNewWriterNoTUICombinedExportsIncludeConsoleJSONAndHTML(t *testing.T) {
	tmpDir := t.TempDir()
	sink, err := NewWriter(config.OutputConfig{
		Format:  "html,json",
		NoTUI:   true,
		JSONOut: filepath.Join(tmpDir, "report.json"),
		HTMLOut: filepath.Join(tmpDir, "report.html"),
	})
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	defer sink.Close()

	multi, ok := sink.(*MultiWriter)
	if !ok {
		t.Fatalf("expected MultiWriter for html,json + no_tui, got %T", sink)
	}
	if len(multi.sinks) != 3 {
		t.Fatalf("expected 3 sinks for html,json + no_tui, got %d", len(multi.sinks))
	}
	if _, ok := multi.sinks[0].(*ConsoleWriter); !ok {
		t.Fatalf("expected first sink to be ConsoleWriter, got %T", multi.sinks[0])
	}
	if _, ok := multi.sinks[1].(*JSONWriter); !ok {
		t.Fatalf("expected second sink to be JSONWriter, got %T", multi.sinks[1])
	}
	if _, ok := multi.sinks[2].(*HTMLWriter); !ok {
		t.Fatalf("expected third sink to be HTMLWriter, got %T", multi.sinks[2])
	}
}

func TestConsoleWriterOmitsSupportingFindingsFromLiveOutput(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewConsoleWriter(&buf, nil)
	for _, finding := range []scanner.Finding{
		sampleConfigOnlyFinding(),
		sampleWeakScriptFinding(),
		sampleSSHSupportFinding(),
		sampleBackupExtensionFinding(),
		sampleFinding(),
	} {
		if err := writer.WriteFinding(finding); err != nil {
			t.Fatalf("WriteFinding returned error: %v", err)
		}
	}

	out := buf.String()
	if strings.Contains(out, "filename.sensitive_config_names") {
		t.Fatalf("expected config-only finding to stay out of live console output, got:\n%s", out)
	}
	if strings.Contains(out, "extension.script_extensions") {
		t.Fatalf("expected weak script artifact to stay out of live console output, got:\n%s", out)
	}
	if strings.Contains(out, "filename.ssh_supporting_artifacts") {
		t.Fatalf("expected ssh supporting artifact to stay out of live console output, got:\n%s", out)
	}
	if strings.Contains(out, "extension.database_and_backup_extensions") {
		t.Fatalf("expected generic backup extension artifact to stay out of live console output, got:\n%s", out)
	}
	if !strings.Contains(out, "content.synthetic_password") {
		t.Fatalf("expected actionable finding to remain in live console output, got:\n%s", out)
	}
}

func TestJSONWriterIncludesSQLiteMetadataAndCorrelation(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewJSONWriter(&buf, nil, true)
	if err := writer.WriteFinding(sampleSQLiteFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSQLiteSupportFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	foundSQLite := false
	foundCorrelation := false
	for _, finding := range report.Findings {
		if finding.DatabaseFilePath == "Apps/payroll-cache.sqlite3" && finding.DatabaseTable == "accounts" && finding.DatabaseColumn == "password" {
			foundSQLite = true
		}
		if finding.RuleID == "correlation.database.sqlite_exposure" {
			foundCorrelation = true
		}
	}
	if !foundSQLite || !foundCorrelation {
		t.Fatalf("expected sqlite metadata and correlation finding, got %#v", report.Findings)
	}
}

func TestHTMLWriterRendersSQLiteMetadata(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer, err := NewHTMLWriter(&buf, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.WriteFinding(sampleSQLiteFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"Database File", "payroll-cache.sqlite3", "Database Table", "accounts", "Database Column", "password", "Database Row Context", "username=svc_payroll"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected html output to contain %q", want)
		}
	}
}

func TestCSVWriterEmitsHeaderAndFindingRow(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewCSVWriter(&buf, nil)
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected header and one row, got %d rows", len(rows))
	}
	if rows[0][0] != "host" || rows[1][0] != "dc01" {
		t.Fatalf("unexpected csv contents: %#v", rows)
	}
}

func TestMarkdownWriterGeneratesSummary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	writer := NewMarkdownWriter(&buf, nil)
	writer.RecordHost("dc01")
	writer.RecordShare("dc01", "SYSVOL")
	writer.RecordFile(scanner.FileMetadata{Host: "dc01", Share: "SYSVOL", FilePath: "Policies/Groups.xml"})
	if err := writer.WriteFinding(sampleFinding()); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"# Snablr Scan Summary", "## Summary", "## Categories", "## Findings", "Synthetic Password", "Domain policies and scripts"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected markdown output to contain %q", want)
		}
	}
}

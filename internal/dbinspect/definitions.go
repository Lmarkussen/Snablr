package dbinspect

import "regexp"

var (
	quotedValueRegex = regexp.MustCompile(`"([^"\r\n]{8,})"|'([^'\r\n]{8,})'`)
	tnsAliasRegex    = regexp.MustCompile(`(?im)^\s*([A-Za-z0-9_.-]+)\s*=\s*\(DESCRIPTION\b`)
	tnsHostRegex     = regexp.MustCompile(`(?i)\bHOST\s*=\s*([^) \t\r\n]+)`)
	tnsPortRegex     = regexp.MustCompile(`(?i)\bPORT\s*=\s*([0-9]{2,5})`)
	tnsServiceRegex  = regexp.MustCompile(`(?i)\bSERVICE_NAME\s*=\s*([^) \t\r\n]+)`)
	tnsSIDRegex      = regexp.MustCompile(`(?i)\bSID\s*=\s*([^) \t\r\n]+)`)
	jdbcOracleRegex  = regexp.MustCompile(`(?i)^jdbc:oracle:[^@]+@(?://)?([^:/;]+)(?::([0-9]{2,5}))?/([A-Za-z0-9_.-]+)$`)
	passwordKVRegex  = regexp.MustCompile(`(?i)\b(password|pwd)\s*=\s*([^;\r\n]+)`)
)

var exactArtifactFiles = map[string]artifactDefinition{
	"tnsnames.ora": {
		id:          "dbinspect.artifact.oracle_tnsnames",
		name:        "Oracle TNS Configuration Artifact",
		description: "This file is a high-confidence Oracle Net configuration artifact.",
		ecosystem:   "oracle",
		match:       "tnsnames.ora",
	},
	"sqlnet.ora": {
		id:          "dbinspect.artifact.oracle_sqlnet",
		name:        "Oracle SQL*Net Configuration Artifact",
		description: "This file is a high-confidence Oracle client network configuration artifact.",
		ecosystem:   "oracle",
		match:       "sqlnet.ora",
	},
	"odbc.ini": {
		id:          "dbinspect.artifact.odbc_ini",
		name:        "ODBC DSN Configuration Artifact",
		description: "This file is a high-confidence ODBC DSN configuration artifact.",
		ecosystem:   "odbc",
		match:       "odbc.ini",
	},
	"odbcinst.ini": {
		id:          "dbinspect.artifact.odbcinst_ini",
		name:        "ODBC Driver Configuration Artifact",
		description: "This file is a high-confidence ODBC driver registration artifact.",
		ecosystem:   "odbc",
		match:       "odbcinst.ini",
	},
}

var extensionArtifacts = map[string]artifactDefinition{
	".dsn": {
		id:          "dbinspect.artifact.odbc_dsn",
		name:        "ODBC DSN Definition Artifact",
		description: "This file extension is a high-confidence ODBC DSN definition artifact.",
		ecosystem:   "odbc",
	},
	".udl": {
		id:          "dbinspect.artifact.udl",
		name:        "Universal Data Link Artifact",
		description: "This file extension commonly stores OLE DB database connection details.",
		ecosystem:   "oledb",
	},
	".accdb": {
		id:          "dbinspect.artifact.access_accdb",
		name:        "Microsoft Access Database Artifact",
		description: "This file extension is a high-confidence Microsoft Access database artifact.",
		ecosystem:   "access",
	},
	".mdb": {
		id:          "dbinspect.artifact.access_mdb",
		name:        "Microsoft Access Database Artifact",
		description: "This file extension is a high-confidence Microsoft Access database artifact.",
		ecosystem:   "access",
	},
	".sqlite": {
		id:          "dbinspect.artifact.sqlite_db",
		name:        "SQLite Database Artifact",
		description: "This file extension is a high-confidence SQLite database artifact.",
		ecosystem:   "sqlite",
	},
	".sqlite3": {
		id:          "dbinspect.artifact.sqlite3_db",
		name:        "SQLite Database Artifact",
		description: "This file extension is a high-confidence SQLite database artifact.",
		ecosystem:   "sqlite",
	},
	".db3": {
		id:          "dbinspect.artifact.sqlite_db3",
		name:        "SQLite Database Artifact",
		description: "This file extension is commonly used for SQLite databases.",
		ecosystem:   "sqlite",
	},
	".mdf": {
		id:          "dbinspect.artifact.mssql_mdf",
		name:        "MSSQL Data File Artifact",
		description: "This file extension is a high-confidence Microsoft SQL Server data-file artifact.",
		ecosystem:   "mssql",
	},
	".ndf": {
		id:          "dbinspect.artifact.mssql_ndf",
		name:        "MSSQL Secondary Data File Artifact",
		description: "This file extension is a high-confidence Microsoft SQL Server secondary data-file artifact.",
		ecosystem:   "mssql",
	},
	".ldf": {
		id:          "dbinspect.artifact.mssql_ldf",
		name:        "MSSQL Log File Artifact",
		description: "This file extension is a high-confidence Microsoft SQL Server log-file artifact.",
		ecosystem:   "mssql",
	},
	".bacpac": {
		id:          "dbinspect.artifact.mssql_bacpac",
		name:        "MSSQL BACPAC Artifact",
		description: "This file extension is a high-confidence Microsoft SQL Server export artifact.",
		ecosystem:   "mssql",
	},
	".dacpac": {
		id:          "dbinspect.artifact.mssql_dacpac",
		name:        "MSSQL DACPAC Artifact",
		description: "This file extension is a high-confidence Microsoft SQL Server package artifact.",
		ecosystem:   "mssql",
	},
}

var backupArtifactExtensions = map[string]string{
	".bak":  "mssql",
	".dump": "postgresql",
	".dmp":  "oracle",
}

var textLikeExtensions = map[string]struct{}{
	".conf":       {},
	".config":     {},
	".cnf":        {},
	".dsn":        {},
	".env":        {},
	".ini":        {},
	".json":       {},
	".ora":        {},
	".properties": {},
	".txt":        {},
	".udl":        {},
	".xml":        {},
	".yaml":       {},
	".yml":        {},
}

var dbHintTokens = []string{
	"database",
	"sql",
	"mssql",
	"mysql",
	"pgsql",
	"postgres",
	"oracle",
	"sqlite",
	"odbc",
	"dsn",
	"jdbc",
	"connection",
}

var databaseBackupTokens = []string{
	"database",
	"sql",
	"mssql",
	"mysql",
	"pgsql",
	"postgres",
	"oracle",
	"sqlite",
	"dbbackup",
	"db-backup",
	"backupset",
}

var placeholderTokens = []string{
	"changeme",
	"placeholder",
	"replace_me",
	"replace-me",
	"replace_this",
	"replace-this",
	"your_password",
	"your-password",
	"your_username",
	"your-username",
	"your_server",
	"your-server",
	"your_database",
	"your-database",
}

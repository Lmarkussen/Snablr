package planner

import (
	"path/filepath"
	"strings"
)

func scoreHost(input HostInput) (int, []string) {
	score := 10
	reasons := []string{"base host priority"}

	switch normalizedSource(input.Source) {
	case "cli":
		score += 25
		reasons = append(reasons, "explicit CLI target")
	case "file":
		score += 15
		reasons = append(reasons, "target supplied from file")
	case "ldap":
		score += 10
		reasons = append(reasons, "discovered from LDAP")
	}

	if strings.Contains(strings.ToLower(input.Source), "dfs") {
		score += 35
		reasons = append(reasons, "DFS-related discovery source")
	}

	host := strings.ToLower(strings.TrimSpace(input.Host))
	switch {
	case containsAny(host, "fs", "files", "file", "nas", "storage"):
		score += 20
		reasons = append(reasons, "hostname suggests file storage role")
	case containsAny(host, "dc", "domain", "ad"):
		score += 10
		reasons = append(reasons, "hostname suggests directory services role")
	}

	return score, reasons
}

func scoreShare(input ShareInput) (int, []string) {
	score := 10
	reasons := []string{"base share priority"}

	share := strings.ToLower(strings.TrimSpace(input.Share))
	if input.PrioritizeADShares {
		switch share {
		case "sysvol":
			score += 100
			reasons = append(reasons, "SYSVOL is high-value for policy and config review")
		case "netlogon":
			score += 95
			reasons = append(reasons, "NETLOGON commonly contains scripts and deployment material")
		}
	}

	switch {
	case containsAny(share, "finance", "fin", "payroll", "hr", "personnel", "legal", "contracts"):
		score += 45
		reasons = append(reasons, "share name suggests business-sensitive content")
	case containsAny(share, "admin", "ops", "it", "scripts", "deploy", "config", "backup", "export", "archive"):
		score += 30
		reasons = append(reasons, "share name suggests operational or sensitive material")
	}

	if strings.Contains(strings.ToLower(input.Source), "dfs") {
		score += 35
		reasons = append(reasons, "DFS-discovered enterprise share")
	}

	return score, reasons
}

func scoreFile(input FileInput) (int, []string) {
	score := 10
	reasons := []string{"base file priority"}

	path := strings.ToLower(filepath.ToSlash(strings.TrimSpace(input.Path)))
	ext := normalizeExtension(input.Extension)

	if input.PrioritizeADShares {
		switch strings.ToLower(strings.TrimSpace(input.Share)) {
		case "sysvol":
			score += 35
			reasons = append(reasons, "file is under SYSVOL")
		case "netlogon":
			score += 30
			reasons = append(reasons, "file is under NETLOGON")
		}

		switch {
		case containsAny(path, "policies/", "/policies/"):
			score += 30
			reasons = append(reasons, "path is under Policies")
		case containsAny(path, "preferences/", "/preferences/"):
			score += 28
			reasons = append(reasons, "path is under Preferences")
		case containsAny(path, "scripts/", "/scripts/"):
			score += 24
			reasons = append(reasons, "path is under Scripts")
		}
	}

	switch {
	case containsAny(path, "secret", "password", "passwd", "token", "key", "cred", "vpn"):
		score += 55
		reasons = append(reasons, "path suggests credential or secret material")
	case containsAny(path, "config", "settings", "unattend", "sysprep", "groups.xml", "registry.xml", "scripts.ini"):
		score += 40
		reasons = append(reasons, "path suggests configuration or policy review material")
	case containsAny(path, "backup", "export", "dump", "archive", "snapshot"):
		score += 28
		reasons = append(reasons, "path suggests backup or export material")
	case containsAny(path, "finance", "payroll", "hr", "employee", "invoice", "customer", "contract"):
		score += 35
		reasons = append(reasons, "path suggests business-sensitive content")
	case containsAny(path, "admin", "ops", "deploy", "bootstrap", "provision", "script"):
		score += 22
		reasons = append(reasons, "path suggests administrative or deployment content")
	}

	switch ext {
	case ".key", ".pem", ".p12", ".pfx", ".jks":
		score += 55
		reasons = append(reasons, "extension suggests key or certificate material")
	case ".env", ".config", ".conf", ".ini", ".json", ".toml", ".xml", ".yaml", ".yml", ".tfvars":
		score += 35
		reasons = append(reasons, "extension suggests configuration content")
	case ".ps1", ".psm1", ".sh", ".py", ".cmd", ".bat":
		score += 24
		reasons = append(reasons, "extension suggests script content")
	case ".sql", ".db", ".sqlite", ".sqlite3", ".bak", ".csv", ".tsv", ".xls", ".xlsx":
		score += 18
		reasons = append(reasons, "extension suggests export, backup, or database content")
	}

	if strings.Contains(strings.ToLower(input.Source), "dfs") {
		score += 10
		reasons = append(reasons, "discovered through DFS-related source")
	}

	return score, reasons
}

func containsAny(value string, parts ...string) bool {
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

func normalizedSource(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeExtension(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, ".") {
		return value
	}
	return "." + value
}

func PriorityBand(value int) string {
	switch {
	case value >= 120:
		return "critical"
	case value >= 80:
		return "high"
	case value >= 40:
		return "medium"
	default:
		return "low"
	}
}

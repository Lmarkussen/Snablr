package backupinspect

import (
	"strings"

	"snablr/internal/rules"
)

type pathFamily struct {
	id          string
	name        string
	description string
	token       string
	severity    string
	tags        []string
}

var pathFamilies = []pathFamily{
	{
		id:          "backupinspect.path.windowsimagebackup",
		name:        "WindowsImageBackup Exposure Path",
		description: "This path is inside a WindowsImageBackup family, which can expose full system-state or disk-backup content including credential-relevant artifacts.",
		token:       "/windowsimagebackup/",
		severity:    "high",
		tags:        []string{"backup", "windows", "artifact:backup-family", "backup-family:windowsimagebackup"},
	},
	{
		id:          "backupinspect.path.system_volume_information",
		name:        "System Volume Information Exposure Path",
		description: "This path is inside System Volume Information, which can expose shadow-copy or restore data that includes sensitive system state.",
		token:       "/system volume information/",
		severity:    "high",
		tags:        []string{"backup", "windows", "artifact:backup-family", "backup-family:system-volume-information"},
	},
	{
		id:          "backupinspect.path.regback",
		name:        "RegBack Exposure Path",
		description: "This path is inside a RegBack family, which can expose copied registry hives such as SAM, SYSTEM, or SECURITY.",
		token:       "/regback/",
		severity:    "high",
		tags:        []string{"backup", "windows", "artifact:backup-family", "backup-family:regback"},
	},
	{
		id:          "backupinspect.path.windows_repair",
		name:        "Windows Repair Hive Exposure Path",
		description: "This path is inside a Windows repair hive location, which can contain copied registry hives used for offline credential extraction workflows.",
		token:       "/windows/repair/",
		severity:    "high",
		tags:        []string{"backup", "windows", "artifact:backup-family", "backup-family:windows-repair"},
	},
}

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(Candidate) bool {
	return false
}

func (Inspector) InspectMetadata(candidate Candidate) []Match {
	normalized := normalizedPath(candidate.FilePath)
	if normalized == "" {
		return nil
	}

	matches := make([]Match, 0, 1)
	for _, family := range pathFamilies {
		if !strings.Contains(normalized, family.token) {
			continue
		}
		matches = append(matches, Match{
			ID:                  family.id,
			Name:                family.name,
			Description:         family.description,
			RuleType:            "filename",
			SignalType:          "validated",
			Severity:            family.severity,
			Confidence:          "high",
			Category:            "backup-exposure",
			Match:               family.token,
			MatchedText:         normalized,
			MatchedTextRedacted: normalized,
			Snippet:             normalized,
			Context:             normalized,
			ContextRedacted:     normalized,
			Explanation:         family.description,
			Remediation:         "Restrict access to system-state backups and copied hive locations, remove unnecessary backup copies from shared storage, and review whether the exposed backup path contains credential-relevant material.",
			Tags:                append([]string{}, family.tags...),
		})
	}
	return matches
}

func normalizedPath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), `\`, `/`)
	return strings.ToLower(rules.NormalizePath(path))
}

func BackupContext(path string) string {
	normalized := normalizedPath(path)
	if normalized == "" {
		return ""
	}
	for _, token := range []string{
		"/windowsimagebackup/",
		"/system volume information/",
		"/windows/system32/config/regback/",
		"/regback/",
		"/windows/repair/",
	} {
		if idx := strings.Index(normalized, token); idx >= 0 {
			return strings.Trim(normalized[:idx+len(token)], "/")
		}
	}
	return ""
}

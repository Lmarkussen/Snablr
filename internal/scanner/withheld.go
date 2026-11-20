package scanner

import (
	"path"
	"strings"
)

// Stealth mode reports some files by name only. Public detection rules
// alert when files with these names or extensions are opened over SMB
// (Windows event 5145): credential stores (SAM, SYSTEM, SECURITY, ntds.dit,
// lsass dumps) and sensitive file types (dumps, Kerberos tickets, mailbox
// and database stores, backups, RDP files).

var withheldNames = map[string]struct{}{
	"sam": {}, "system": {}, "security": {}, "ntds.dit": {},
}

// withheldNameSuffixes are copies of the hive and ntds names ("SAM.sav",
// "ntds.dit.bak").
var withheldNameSuffixes = []string{".sav", ".save", ".bak", ".old", ".hiv", ".copy"}

var withheldExtensions = map[string]struct{}{
	".bak": {}, ".dmp": {}, ".mdmp": {}, ".hdmp": {}, ".edb": {}, ".kirbi": {}, ".ccache": {},
	".msg": {}, ".nsf": {}, ".nst": {}, ".oab": {}, ".ost": {}, ".pst": {}, ".rdp": {}, ".hiv": {},
}

// ContentWithheld reports whether stealth mode reports a file by name only.
func ContentWithheld(meta FileMetadata) bool {
	name := strings.ToLower(strings.TrimSpace(meta.Name))
	if name == "" {
		name = strings.ToLower(path.Base(strings.ReplaceAll(meta.FilePath, `\`, "/")))
	}
	if _, ok := withheldNames[name]; ok {
		return true
	}
	for base := range withheldNames {
		for _, suffix := range withheldNameSuffixes {
			if name == base+suffix {
				return true
			}
		}
	}
	if strings.Contains(name, "lsass") {
		return true
	}
	_, ok := withheldExtensions[path.Ext(name)]
	return ok
}

func (e *Engine) withholdsContent(meta FileMetadata) bool {
	return e != nil && e.opts.WithholdSensitiveContent && ContentWithheld(meta)
}

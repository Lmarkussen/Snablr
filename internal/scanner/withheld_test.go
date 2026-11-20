package scanner

import (
	"path/filepath"
	"testing"

	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestContentWithheldNames(t *testing.T) {
	for _, name := range []string{
		"SAM", "SYSTEM", "SECURITY", "ntds.dit", "SAM.sav", "SYSTEM.bak", "ntds.dit.bak",
		"lsass.dmp", "lsass.zip", "memory.dmp", "admin.kirbi", "mailbox.pst", "archive.ost",
		"priv.edb", "web.config.bak", "jump.rdp", "note.msg", "krb5cc.ccache",
	} {
		if !ContentWithheld(FileMetadata{Name: name}) {
			t.Errorf("%s is not withheld", name)
		}
	}
	for _, name := range []string{
		"system.ini", "security.config", "samples.txt", "SystemInfo.txt", "Groups.xml",
		"unattend.xml", "web.config", "id_rsa", "deploy.ppk", "secrets.yml", "sam.ps1",
	} {
		if ContentWithheld(FileMetadata{Name: name}) {
			t.Errorf("%s is withheld", name)
		}
	}
}

// Withheld files are never read but still reported by name; without the
// option the same files are read as before.
func TestEngineWithholdsSensitiveContent(t *testing.T) {
	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stealth := NewEngine(Options{WithholdSensitiveContent: true}, manager, nil, logx.New("error"))
	normal := NewEngine(Options{}, manager, nil, logx.New("error"))
	hive := FileMetadata{Host: "fs01", Share: "Backup", FilePath: "Servers/DC01/Windows/System32/config/SAM", Name: "SAM", Size: 65536}
	if stealth.NeedsContent(hive) {
		t.Error("stealth engine asks for hive content")
	}
	if !normal.NeedsContent(hive) {
		t.Error("normal engine no longer asks for hive content")
	}
	evaluation := stealth.Evaluate(hive, nil)
	if len(actionableRules(evaluation.Findings)) == 0 {
		t.Errorf("withheld hive not reported as actionable by name: %v", findingRuleSet(evaluation.Findings))
	}
	if evaluation.NeedContent {
		t.Error("withheld hive left waiting for content")
	}

	config := FileMetadata{Host: "fs01", Share: "IT", FilePath: "Deploy/web.config", Name: "web.config", Extension: ".config", Size: 2048}
	if stealth.NeedsContent(config) != normal.NeedsContent(config) {
		t.Error("stealth changes content reads for an ordinary file")
	}
}

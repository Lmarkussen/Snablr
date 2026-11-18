package rules

import (
	"path/filepath"
	"testing"
)

func TestPathMatchesAnyUsesWholeSegments(t *testing.T) {
	cases := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"Temp/notes.txt", []string{"temp"}, true},
		{"Users/a/AppData/Local/Temp/x.txt", []string{"temp"}, true},
		{"IT/Templates/unattend.xml", []string{"temp"}, false},
		{"Users/Robin/passwords.txt", []string{"bin"}, false},
		{"Finance/Vendors/logins.xlsx", []string{"vendor"}, false},
		{"IT/Distribution/deploy.ps1", []string{"dist"}, false},
		{"app/bin/settings.json", []string{"bin"}, true},
		{"src/node_modules/pkg/index.js", []string{"node_modules"}, true},
		{"C/Windows/System32/config/SAM", []string{"windows/system32/config"}, true},
		{"Backup/windows-system32-config/SAM", []string{"windows/system32/config"}, false},
		{"Docs/veiledning-for-passord.docx", []string{"*veiledning*"}, true},
		{"Docs/passord.txt", []string{"*veiledning*"}, false},
		{`Share\TEMP\x.txt`, []string{"temp"}, true},
		{"anything.txt", []string{""}, false},
	}
	for _, tc := range cases {
		if got := PathMatchesAny(tc.path, tc.patterns); got != tc.want {
			t.Errorf("PathMatchesAny(%q, %q) = %v, want %v", tc.path, tc.patterns, got, tc.want)
		}
	}
}

// Generic location tokens in the default exclusion rules previously matched
// as substrings, silently skipping folders such as Templates, Robin, Vendors
// and Distribution. They must only skip whole matching folders.
func TestDefaultExclusionsDoNotSkipFoldersThatOnlyContainToken(t *testing.T) {
	manager, _, err := LoadManager([]string{filepath.Join("..", "..", "configs", "rules", "default")}, false, ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}
	inspected := []string{
		"IT/Templates/unattend.xml",
		"Users/Robin/Documents/passwords.txt",
		"Finance/Vendors/portal-logins.txt",
		"IT/Distribution/deploy/settings.config",
		"Projects/Targets/q3.txt",
		"Facilities/Buildings/access.txt",
		"Users/a/AppData/Roaming/Microsoft/Teams/msal.cache",
	}
	for _, path := range inspected {
		if skip, rule := manager.ShouldExclude(Candidate{Path: path, Name: filepath.Base(path), Extension: filepath.Ext(path)}); skip {
			t.Errorf("%s was skipped by %s", path, rule.ID)
		}
	}
	skipped := []string{
		"Users/a/AppData/Local/Temp/setup.log",
		"build/tmp/output.txt",
		"web/node_modules/pkg/config.js",
		"app/bin/Debug/app.config",
		"Users/a/AppData/Local/Microsoft/Windows/INetCache/IE/x.htm",
	}
	for _, path := range skipped {
		if skip, _ := manager.ShouldExclude(Candidate{Path: path, Name: filepath.Base(path), Extension: filepath.Ext(path)}); !skip {
			t.Errorf("%s was not skipped", path)
		}
	}
}

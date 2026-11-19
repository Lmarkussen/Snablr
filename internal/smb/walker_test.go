package smb

import "testing"

func TestWalkerExcludePathRespectsDirectoryBoundaries(t *testing.T) {
	opts := WalkOptions{ExcludePaths: []string{"1/2/3"}}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"1/2/3", false},
		{"1/2/3/nested", false},
		{"1/2/30", true},
		{"1/2", true},
	} {
		if got := shouldDescendRemoteDir(tc.path, 3, opts, 64); got != tc.want {
			t.Fatalf("should descend %q = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// "--path Reports/" (the form shown in the scan help) must select the same
// files as "--path Reports"; previously the trailing slash made the walker
// descend into the folder but reject every file in it.
func TestWalkerScopePrefixesIgnoreTrailingSeparators(t *testing.T) {
	for _, prefix := range []string{"Reports", "Reports/", `Reports\`, "/Reports/"} {
		include := WalkOptions{IncludePaths: []string{prefix}}
		if !shouldDescendRemoteDir("Reports", 1, include, 64) {
			t.Fatalf("include %q: did not descend into Reports", prefix)
		}
		if !shouldIncludeRemoteFile("Reports/q1/summary.txt", 2, include, 64) {
			t.Fatalf("include %q: rejected a file inside Reports", prefix)
		}
		if shouldIncludeRemoteFile("ReportsArchive/summary.txt", 1, include, 64) {
			t.Fatalf("include %q: matched a sibling sharing the name prefix", prefix)
		}

		exclude := WalkOptions{ExcludePaths: []string{prefix}}
		if shouldDescendRemoteDir("Reports", 1, exclude, 64) {
			t.Fatalf("exclude %q: still descended into Reports", prefix)
		}
		if shouldIncludeRemoteFile("Reports/summary.txt", 1, exclude, 64) {
			t.Fatalf("exclude %q: still included a file inside Reports", prefix)
		}
	}
}

func TestWalkerDynamicDescentPredicateIsRecheckedAtBoundary(t *testing.T) {
	allowed := true
	opts := WalkOptions{ShouldDescend: func(string) bool { return allowed }}
	if !shouldDescendRemoteDir("1/2/3", 3, opts, 64) {
		t.Fatal("expected initial directory descent")
	}
	allowed = false
	if opts.ShouldDescend("1/2/3") {
		t.Fatal("dynamic skip predicate still allowed descent")
	}
}

// SMB paths are case-insensitive; "--path finance" must select "Finance"
// instead of silently scanning nothing.
func TestWalkerScopePrefixesAreCaseInsensitive(t *testing.T) {
	include := WalkOptions{IncludePaths: []string{"finance/EXPORTS"}}
	if !shouldDescendRemoteDir("Finance", 1, include, 64) || !shouldDescendRemoteDir("Finance/Exports", 2, include, 64) {
		t.Fatal("did not descend into a differently cased include path")
	}
	if !shouldIncludeRemoteFile("Finance/Exports/q1.xlsx", 2, include, 64) {
		t.Fatal("rejected a file under a differently cased include path")
	}
	exclude := WalkOptions{ExcludePaths: []string{"FINANCE"}}
	if shouldDescendRemoteDir("Finance", 1, exclude, 64) || shouldIncludeRemoteFile("finance/a.txt", 1, exclude, 64) {
		t.Fatal("differently cased exclude path was ignored")
	}
}

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

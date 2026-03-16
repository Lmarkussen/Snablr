package seed

import (
	"fmt"
	"strings"
	"testing"

	"snablr/internal/smb"
)

func TestShouldIncludeSeedShareExcludesAdministrativeSharesByDefault(t *testing.T) {
	t.Parallel()

	if shouldIncludeSeedShare(smb.ShareInfo{Name: "C$"}, nil, false) {
		t.Fatal("expected C$ to be excluded by default")
	}
	if shouldIncludeSeedShare(smb.ShareInfo{Name: "ADMIN$"}, nil, false) {
		t.Fatal("expected ADMIN$ to be excluded by default")
	}
	if !shouldIncludeSeedShare(smb.ShareInfo{Name: "Finance"}, nil, false) {
		t.Fatal("expected ordinary shares to remain eligible")
	}
}

func TestShouldIncludeSeedShareAllowsExplicitAdministrativeShare(t *testing.T) {
	t.Parallel()

	shareAllow := buildShareAllowSet([]string{"C$"})
	if !shouldIncludeSeedShare(smb.ShareInfo{Name: "C$"}, shareAllow, false) {
		t.Fatal("expected explicitly requested admin share to be included")
	}
	if shouldIncludeSeedShare(smb.ShareInfo{Name: "Finance"}, shareAllow, false) {
		t.Fatal("expected explicit share allow list to restrict other shares")
	}
}

func TestShouldIncludeSeedShareAllowsAdminOverride(t *testing.T) {
	t.Parallel()

	if !shouldIncludeSeedShare(smb.ShareInfo{Name: "PRINT$"}, nil, true) {
		t.Fatal("expected include-admin-shares override to allow PRINT$")
	}
}

func TestLogSeedSummaryReportsCounts(t *testing.T) {
	t.Parallel()

	lines := make([]string, 0)
	opts := WriteOptions{
		Logf: func(format string, args ...any) {
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	stats := newSeedRunStats(375)
	stats.recordWritten("finance", "fs01", "Finance")
	stats.recordWritten("finance", "fs01", "Finance")
	stats.recordWritten("sql", "fs01", "SQL")
	stats.recordSkipped()

	logSeedSummary(opts, stats, Manifest{Entries: make([]SeedManifestEntry, 4)})

	joined := strings.Join(lines, "\n")
	for _, fragment := range []string{
		"seed summary: candidates=375 written=3 skipped=1 dry-run=0 manifest-entries=4",
		"written by category: finance=2",
		"written by category: sql=1",
		"written by share: fs01/Finance=2",
		"written by share: fs01/SQL=1",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("expected log output to contain %q, got:\n%s", fragment, joined)
		}
	}
}

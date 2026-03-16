package seed

import (
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

package wincredinspect

import "testing"

func TestInspectMetadataDetectsCredentialStorePaths(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Users\Alice\AppData\Roaming\Microsoft\Credentials\D0C0A11C`,
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "wincredinspect.path.credentials" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
	if matches[0].Category != "windows-credentials" || matches[0].Confidence != "high" {
		t.Fatalf("expected high-confidence windows credential finding, got %#v", matches[0])
	}
}

func TestInspectMetadataDetectsBackupVariantPaths(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Archive/ProfileCopy/Bob/AppData/Local/Microsoft/Vault/0A1B2C3D/Policy.vpol`,
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "wincredinspect.path.vault" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
}

func TestInspectMetadataNormalizesCaseAndSeparators(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `USERS/ALICE/APPDATA/LOCAL/MICROSOFT/PROTECT/S-1-5-21/MASTERKEY`,
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "wincredinspect.path.protect" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
}

func TestInspectMetadataIgnoresLookalikePaths(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Users/Alice/Documents/Credentials/readme.txt`,
	})
	if len(matches) != 0 {
		t.Fatalf("expected lookalike path to stay quiet, got %#v", matches)
	}
}

func TestProfileContextExtractsProfilePrefix(t *testing.T) {
	t.Parallel()

	if got := ProfileContext(`Users\Alice\AppData\Roaming\Microsoft\Credentials\A1B2`); got != "users/alice" {
		t.Fatalf("unexpected profile context: %q", got)
	}
	if got := ProfileContext(`Archive/ProfileCopy/Bob/AppData/Local/Microsoft/Vault/GUID/file.vcrd`); got != "archive/profilecopy/bob" {
		t.Fatalf("unexpected backup profile context: %q", got)
	}
}

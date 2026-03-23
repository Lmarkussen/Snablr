package backupinspect

import "testing"

func TestInspectMetadataMatchesExactBackupFamilies(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Backups\SystemState\WindowsImageBackup\DC01\Backup 2025-01-01\C\Windows\System32\config\SAM`,
		Name:     "SAM",
	})
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %#v", matches)
	}
	if matches[0].ID != "backupinspect.path.windowsimagebackup" {
		t.Fatalf("unexpected match: %#v", matches[0])
	}
}

func TestInspectMetadataIgnoresNearMissBackupPaths(t *testing.T) {
	t.Parallel()

	inspector := New()
	matches := inspector.InspectMetadata(Candidate{
		FilePath: `Archive/WindowsImageBackup-Notes/readme.txt`,
		Name:     "readme.txt",
	})
	if len(matches) != 0 {
		t.Fatalf("expected no match for near-miss path, got %#v", matches)
	}
}

func TestBackupContextNormalizesWindowsPaths(t *testing.T) {
	t.Parallel()

	got := BackupContext(`Archive\SystemCopies\Windows\System32\config\RegBack\SYSTEM.old`)
	want := "archive/systemcopies/windows/system32/config/regback"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

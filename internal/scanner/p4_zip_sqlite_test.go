package scanner

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"testing"

	"snablr/internal/archiveinspect"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestP4ArchiveEvaluationStructurallyInspectsSQLiteMember(t *testing.T) {
	t.Parallel()

	sqlite := make([]byte, 4096)
	copy(sqlite, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(sqlite[16:18], 4096)
	sqlite[18], sqlite[19], sqlite[21], sqlite[22], sqlite[23] = 1, 1, 64, 32, 32
	binary.BigEndian.PutUint32(sqlite[28:32], 1)
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("nested/opaque.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(sqlite); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine(Options{Archives: archiveinspect.Options{
		Enabled: true, AutoZIPMaxSize: 10 * 1024 * 1024, MaxZIPSize: 10 * 1024 * 1024,
		MaxMembers: 64, MaxMemberBytes: 512 * 1024, MaxTotalUncompressed: 4 * 1024 * 1024,
		InspectExtensionlessText: true,
	}}, &rules.Manager{}, nil, logx.New("error"))
	evaluation := engine.evaluateArchive(FileMetadata{Host: "host", Share: "share", FilePath: "bundle.zip", Name: "bundle.zip", Extension: ".zip", Size: int64(archive.Len())}, archive.Bytes())
	for _, finding := range evaluation.Findings {
		if finding.RuleID == "dbinspect.artifact.sqlite_structural" {
			if finding.ArchiveMemberPath != "nested/opaque.sqlite" || finding.ArchivePath != "bundle.zip" || finding.ObservationID == "" {
				t.Fatalf("SQLite member provenance or observation identity lost: %#v", finding)
			}
			if finding.MatchedText != "SQLite format 3\x00" {
				t.Fatalf("SQLite structural evidence changed: %q", finding.MatchedText)
			}
			return
		}
	}
	t.Fatalf("expected structural SQLite finding for archive member, got %#v", evaluation.Findings)
}

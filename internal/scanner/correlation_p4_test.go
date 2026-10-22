package scanner

import (
	"testing"

	"snablr/internal/dbinspect"
)

func TestP4DatabaseObservationsRemainDistinctWithinOneSource(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{Host: "fileserver", Share: "configs", FilePath: "app.json", Name: "app.json"}
	matches := []dbinspect.Match{
		{ID: "dbinspect.infrastructure.structured_config", Name: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", Match: "host=prod;database=app", MatchedText: "production", ObservationID: "structured:0:prod"},
		{ID: "dbinspect.infrastructure.structured_config", Name: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", Match: "host=report;database=reporting", MatchedText: "reporting", ObservationID: "structured:1:report"},
	}
	findings := correlateFindings(meta, findingsFromDBMatches(meta, matches))
	if len(findings) != 2 {
		t.Fatalf("distinct database observations collapsed: %#v", findings)
	}
	if findings[0].MatchedText == findings[1].MatchedText || findings[0].ObservationID == findings[1].ObservationID {
		t.Fatalf("distinct observations lost their evidence or identity: %#v", findings)
	}
}

func TestP4DuplicateDatabaseObservationEmissionStillCollapses(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{Host: "fileserver", Share: "configs", FilePath: "app.json", Name: "app.json"}
	match := dbinspect.Match{ID: "dbinspect.infrastructure.structured_config", Name: "Configured endpoint", Category: "database-infrastructure", SignalType: "validated", Confidence: "high", Match: "host=prod;database=app", MatchedText: "production", ObservationID: "structured:0:prod"}
	findings := correlateFindings(meta, findingsFromDBMatches(meta, []dbinspect.Match{match, match}))
	if len(findings) != 1 {
		t.Fatalf("duplicate database observation emission was not deduplicated: %#v", findings)
	}
}

func TestP4DatabaseObservationIDsAreSourceScopedAndStable(t *testing.T) {
	t.Parallel()

	match := dbinspect.Match{
		ID:         "dbinspect.artifact.sqlite_structural",
		Match:      "SQLite format 3\x00",
		LineNumber: 0,
	}
	metas := []FileMetadata{
		{Host: "fileserver", Share: "data", FilePath: "opaque.bin"},
		{Host: "fileserver", Share: "data", FilePath: "extensionless-sqlite"},
		{Host: "fileserver", Share: "data", FilePath: "bundle.zip!nested/opaque.sqlite", ArchivePath: "bundle.zip", ArchiveMemberPath: "nested/opaque.sqlite"},
		{Host: "other-server", Share: "data", FilePath: "opaque.bin"},
		{Host: "fileserver", Share: "other-data", FilePath: "opaque.bin"},
		{Host: "fileserver", Share: "data", FilePath: "first.zip!nested/opaque.sqlite", ArchivePath: "first.zip", ArchiveMemberPath: "nested/opaque.sqlite"},
		{Host: "fileserver", Share: "data", FilePath: "second.zip!nested/opaque.sqlite", ArchivePath: "second.zip", ArchiveMemberPath: "nested/opaque.sqlite"},
		{Host: "fileserver", Share: "data", FilePath: "bundle.zip!other/opaque.sqlite", ArchivePath: "bundle.zip", ArchiveMemberPath: "other/opaque.sqlite"},
	}
	ids := make(map[string]struct{}, len(metas))
	for _, meta := range metas {
		findings := findingsFromDBMatches(meta, []dbinspect.Match{match})
		if len(findings) != 1 || findings[0].ObservationID == "" {
			t.Fatalf("missing source-scoped observation ID for %#v: %#v", meta, findings)
		}
		ids[findings[0].ObservationID] = struct{}{}
		again := findingsFromDBMatches(meta, []dbinspect.Match{match})
		if findings[0].ObservationID != again[0].ObservationID {
			t.Fatalf("observation ID is not stable for %#v: %q != %q", meta, findings[0].ObservationID, again[0].ObservationID)
		}
	}
	if len(ids) != len(metas) {
		t.Fatalf("distinct source observations share an ID: got %d IDs for %d sources", len(ids), len(metas))
	}
}

func TestP4DatabaseObservationIDEncodingAvoidsComponentBoundaryAliases(t *testing.T) {
	t.Parallel()

	match := dbinspect.Match{ID: "dbinspect.artifact.sqlite_structural", Match: "SQLite format 3\x00"}
	left := findingsFromDBMatches(FileMetadata{Host: "ab", Share: "c", FilePath: "file"}, []dbinspect.Match{match})
	right := findingsFromDBMatches(FileMetadata{Host: "a", Share: "bc", FilePath: "file"}, []dbinspect.Match{match})
	if left[0].ObservationID == right[0].ObservationID {
		t.Fatalf("component boundary alias produced identical IDs: %q", left[0].ObservationID)
	}
}

func TestP4StructuralSQLiteFindingSurvivesSupportingArtifact(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{Host: "fileserver", Share: "data", FilePath: "reporting.sqlite3", Name: "reporting.sqlite3", Extension: ".sqlite3"}
	candidate := dbinspect.Candidate{FilePath: meta.FilePath, Name: meta.Name, Extension: meta.Extension, Size: 4096}
	metadata := dbinspect.New().InspectMetadata(candidate)
	content := make([]byte, 4096)
	copy(content, []byte("SQLite format 3\x00"))
	content[16], content[21], content[22], content[23] = 0x10, 64, 32, 32
	content[18], content[19] = 1, 1
	content[28] = 1
	contentMatches := dbinspect.New().InspectContent(candidate, content)
	matches := append(metadata, contentMatches...)
	findings := correlateFindings(meta, findingsFromDBMatches(meta, matches))
	if len(findings) != 2 {
		t.Fatalf("structural and supporting SQLite observations collapsed: %#v", findings)
	}
	seenStructural := false
	seenSupporting := false
	for _, finding := range findings {
		if finding.RuleID == "dbinspect.artifact.sqlite_structural" {
			seenStructural = containsString(finding.Tags, "db:status:confirmed") && finding.SignalType == "validated"
		}
		if finding.RuleID == "dbinspect.artifact.sqlite3_db" {
			seenSupporting = true
		}
	}
	if !seenStructural || !seenSupporting {
		t.Fatalf("SQLite statuses were not preserved: %#v", findings)
	}
}

func TestLegacyCorrelationStillGroupsFindingsWithoutObservationID(t *testing.T) {
	t.Parallel()

	meta := FileMetadata{Host: "fileserver", Share: "configs", FilePath: "app.env", Name: "app.env"}
	findings := correlateFindings(meta, []Finding{
		{RuleID: "content.one", Category: "credentials", MatchedText: "one"},
		{RuleID: "content.two", Category: "credentials", MatchedText: "two"},
	})
	if len(findings) != 1 {
		t.Fatalf("legacy grouping changed for findings without observation IDs: %#v", findings)
	}
}

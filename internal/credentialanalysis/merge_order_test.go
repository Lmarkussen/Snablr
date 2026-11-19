package credentialanalysis

import (
	"context"
	"testing"
)

// The same credential found in several identical files merges into the same
// record whatever order the files were stored in, so reports show the same
// primary location on every run.
func TestMergedCredentialDoesNotDependOnArrivalOrder(t *testing.T) {
	candidate := func(path string) Candidate {
		return Candidate{Verification: Confirmed, CredentialType: "password", Identity: "synthetic-user", Value: "Synthetic-Secret-1!", Host: "fileserver.example.test", Share: "share", Path: path, Source: "test", Evidence: []Evidence{{Path: path, Source: "test"}}}
	}
	files := []Candidate{candidate("copies/c.ini"), candidate("copies/a.ini"), candidate("copies/b.ini")}
	orders := [][]Candidate{
		{files[0], files[1], files[2]},
		{files[2], files[1], files[0]},
		{files[1], files[0], files[2]},
	}
	var analyzed, persisted []string
	for _, order := range orders {
		report := Analyze(order)
		if len(report.Candidates) != 1 {
			t.Fatalf("analysis kept %d records, want 1", len(report.Candidates))
		}
		analyzed = append(analyzed, report.Candidates[0].Path)

		merger, err := NewPersistedMerger()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range order {
			if err := merger.Add(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		}
		var paths []string
		if err := merger.Iterate(context.Background(), func(c Candidate) error {
			paths = append(paths, c.Path)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_ = merger.Close()
		if len(paths) != 1 {
			t.Fatalf("persisted merge kept %d records, want 1", len(paths))
		}
		persisted = append(persisted, paths[0])
	}
	for i := range orders {
		if analyzed[i] != "copies/a.ini" || persisted[i] != "copies/a.ini" {
			t.Fatalf("primary location by arrival order: analyzed=%v persisted=%v", analyzed, persisted)
		}
	}
}

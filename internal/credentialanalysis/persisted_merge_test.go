package credentialanalysis

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPersistedMergerMatchesAnalyzeMergeSemantics(t *testing.T) {
	candidates := []Candidate{
		{Verification: Review, CredentialType: " Password ", Identity: "svc", Value: "secret", Host: "h", Share: "s", Path: "doc.docx!word/a.xml", Evidence: []Evidence{{Path: "doc.docx!word/a.xml"}}},
		{Verification: Confirmed, CredentialType: "password", Identity: "SVC", Value: "secret", Host: "h", Share: "s", Path: "doc.docx!word/b.xml", Evidence: []Evidence{{Path: "doc.docx!word/b.xml"}}},
		{Verification: Confirmed, CredentialType: "password", Identity: "svc", Value: "secret", Host: "other", Share: "s", Path: "other.ini"},
		{Verification: Confirmed, CredentialType: "password", Identity: "other", Value: "secret", Host: "h", Share: "s", Path: "other.ini"},
	}
	want := Analyze(candidates)
	merger, err := NewPersistedMerger()
	if err != nil {
		t.Fatal(err)
	}
	defer merger.Close()
	for _, candidate := range candidates {
		if err := merger.Add(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	var got []Candidate
	if err := merger.Iterate(context.Background(), func(candidate Candidate) error { got = append(got, candidate); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want.Candidates) {
		t.Fatalf("merged count=%d want=%d", len(got), len(want.Candidates))
	}
	for i := range got {
		if !reflect.DeepEqual(got[i], want.Candidates[i]) {
			t.Fatalf("merged[%d]=%+v want=%+v", i, got[i], want.Candidates[i])
		}
	}
	var stored string
	db, err := sql.Open("sqlite3", merger.DiskPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow(`SELECT payload FROM merged LIMIT 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, `"value":"secret"`) {
		t.Fatalf("plaintext credential value persisted in merge payload: %s", stored)
	}
}

func TestPersistedAnalysisMatchesLegacyClassificationAndCounts(t *testing.T) {
	candidates := []Candidate{
		{Verification: Review, CredentialType: "password", Identity: "svc", Value: "secret", Path: "a.ini"},
		{Verification: Confirmed, CredentialType: "password", Identity: "svc", Value: "secret", Path: "b.ini"},
		{Verification: Review, CredentialType: "token", Value: "template", Path: "template.txt"},
		{Verification: Confirmed, CredentialType: "identity_marker", Identity: "svc", Material: MaterialCorrelation, Path: "marker.txt"},
	}
	want := Analyze(candidates)
	analysis, err := NewPersistedAnalysis()
	if err != nil {
		t.Fatal(err)
	}
	defer analysis.Close()
	for _, candidate := range candidates {
		if err := analysis.Add(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	var got []Candidate
	if err := analysis.IterateRecords(context.Background(), func(record PersistedMergedRecord) error {
		got = append(got, record.Candidate)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want.Candidates) {
		t.Fatalf("records=%d want=%d", len(got), len(want.Candidates))
	}
	for i := range got {
		expected := want.Candidates[i]
		expected.Evidence = []Evidence{}
		expected.Locations = []string{}
		if !reflect.DeepEqual(got[i], expected) {
			t.Fatalf("record[%d]=%+v want=%+v", i, got[i], expected)
		}
	}
	stats := analysis.Stats()
	if stats.CandidatesAnalyzed != want.CandidatesAnalyzed || stats.SuppressedPlaceholders != want.SuppressedPlaceholders || stats.SuppressedWeakReview != want.SuppressedWeakReview || stats.DuplicatesMerged != want.DuplicatesMerged {
		t.Fatalf("stats=%+v want candidates=%d suppressed=%d/%d merged=%d", stats, want.CandidatesAnalyzed, want.SuppressedPlaceholders, want.SuppressedWeakReview, want.DuplicatesMerged)
	}
}

func TestPersistedMergerCancellationAndManyGroups(t *testing.T) {
	merger, err := NewPersistedMerger()
	if err != nil {
		t.Fatal(err)
	}
	defer merger.Close()
	for i := 0; i < 250; i++ {
		if err := merger.Add(context.Background(), Candidate{Verification: Confirmed, CredentialType: "token", Identity: "user-" + string(rune(i)), Value: "value-" + string(rune(i)), Path: "file-" + string(rune(i))}); err != nil {
			t.Fatal(err)
		}
	}
	count, err := merger.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 250 {
		t.Fatalf("count=%d", count)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := merger.Iterate(ctx, func(Candidate) error { return nil }); err == nil {
		t.Fatal("expected cancellation")
	}
	if err := merger.Add(context.Background(), Candidate{}); err != nil {
		t.Fatal(err)
	}
	if err := merger.Iterate(context.Background(), nil); err == nil {
		t.Fatal("expected nil visitor error")
	}
}

func TestPersistedMergerClosedErrors(t *testing.T) {
	merger, err := NewPersistedMerger()
	if err != nil {
		t.Fatal(err)
	}
	path := merger.DiskPath()
	if err := merger.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := merger.Count(context.Background()); err == nil {
		t.Fatal("expected count error after close")
	}
	if err := merger.Add(context.Background(), Candidate{CredentialType: "token", Value: "x"}); err == nil {
		t.Fatal("expected add error after close")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary merger database still exists: %v", err)
	}
}

func TestPersistedMergerIndexedLookupAndPagedMembership(t *testing.T) {
	merger, err := NewPersistedMerger()
	if err != nil {
		t.Fatal(err)
	}
	defer merger.Close()
	for i := 0; i < 37; i++ {
		candidate := Candidate{
			Verification:   Confirmed,
			CredentialType: "password",
			Identity:       "shared-user",
			Value:          "same-secret",
			Path:           "file-" + strconv.Itoa(i) + ".ini",
			Evidence:       []Evidence{{RuleID: "rule", Path: "file-" + strconv.Itoa(i) + ".ini"}},
		}
		if err := merger.Add(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		if err := merger.Add(context.Background(), Candidate{
			Verification:   Confirmed,
			CredentialType: "password",
			Identity:       "unrelated-user-" + strconv.Itoa(i),
			Value:          "same-secret",
			Path:           "unrelated-" + strconv.Itoa(i) + ".ini",
		}); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite3", merger.DiskPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var plan string
	var planID, parentID, notUsed int
	if err := db.QueryRow(`EXPLAIN QUERY PLAN SELECT id FROM merged WHERE credential_type=? AND value_hash=?`, "password", merger.valueTag("same-secret")).Scan(&planID, &parentID, &notUsed, &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(plan), "merged_lookup_idx") {
		t.Fatalf("lookup did not use merged_lookup_idx: %s", plan)
	}
	var candidateSet int
	if err := db.QueryRow(`SELECT COUNT(*) FROM merged WHERE credential_type=? AND value_hash=?`, "password", merger.valueTag("same-secret")).Scan(&candidateSet); err != nil {
		t.Fatal(err)
	}
	t.Logf("indexed candidate set for duplicate group=%d of persisted records", candidateSet)
	var storedTag []byte
	if err := db.QueryRow(`SELECT value_hash FROM merged LIMIT 1`).Scan(&storedTag); err != nil {
		t.Fatal(err)
	}
	plainHash := sha256.Sum256([]byte("same-secret"))
	if strings.EqualFold(string(storedTag), string(plainHash[:])) {
		t.Fatal("persisted lookup tag is an unkeyed value hash")
	}

	var record PersistedMergedRecord
	if err := merger.IterateRecords(context.Background(), func(candidate PersistedMergedRecord) error {
		if candidate.EvidenceCount == 37 {
			record = candidate
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if record.EvidenceCount != 37 || record.LocationCount != 37 {
		t.Fatalf("membership counts=%d/%d, want 37/37", record.EvidenceCount, record.LocationCount)
	}
	evidenceCount := 0
	var evidenceCursor EvidenceCursor
	for {
		var more bool
		var err error
		evidenceCursor, more, err = merger.IterateEvidencePage(context.Background(), record.ID, evidenceCursor, 5, func(Evidence) error {
			evidenceCount++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	if evidenceCount != 37 {
		t.Fatalf("paged evidence=%d, want 37", evidenceCount)
	}
	locationCount := 0
	var locationCursor LocationCursor
	for {
		var more bool
		var err error
		locationCursor, more, err = merger.IterateLocationPage(context.Background(), record.ID, locationCursor, 6, func(string) error {
			locationCount++
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !more {
			break
		}
	}
	if locationCount != 37 {
		t.Fatalf("paged locations=%d, want 37", locationCount)
	}
}

func TestPersistedMergerMeasurement(t *testing.T) {
	for _, size := range []int{100, 500, 1000, 2000} {
		candidates := make([]Candidate, size)
		for i := range candidates {
			candidates[i] = Candidate{
				Verification:   Confirmed,
				CredentialType: "token",
				Identity:       "user-" + strconv.Itoa(i),
				Value:          "value-" + strconv.Itoa(i),
				Path:           "file-" + strconv.Itoa(i),
			}
		}
		merger, err := NewPersistedMerger()
		if err != nil {
			t.Fatal(err)
		}
		var maxRSS, maxHeap uint64
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					var stats runtime.MemStats
					runtime.ReadMemStats(&stats)
					if stats.HeapAlloc > maxHeap {
						maxHeap = stats.HeapAlloc
					}
					if rss := processRSSBytes(); rss > maxRSS {
						maxRSS = rss
					}
				case <-stop:
					return
				}
			}
		}()
		insertStart := time.Now()
		for _, candidate := range candidates {
			if err := merger.Add(context.Background(), candidate); err != nil {
				close(stop)
				<-done
				_ = merger.Close()
				t.Fatal(err)
			}
		}
		insertElapsed := time.Since(insertStart)
		iterateStart := time.Now()
		count := 0
		if err := merger.Iterate(context.Background(), func(Candidate) error { count++; return nil }); err != nil {
			close(stop)
			<-done
			_ = merger.Close()
			t.Fatal(err)
		}
		iterateElapsed := time.Since(iterateStart)
		close(stop)
		<-done
		info, err := os.Stat(merger.DiskPath())
		if err != nil {
			t.Fatal(err)
		}
		if count != size {
			t.Fatalf("iterated=%d want=%d", count, size)
		}
		t.Logf("size=%d candidates=%d insert=%s iterate=%s peak_rss=%d bytes peak_heap=%d bytes sqlite=%d bytes", size, len(candidates), insertElapsed, iterateElapsed, maxRSS, maxHeap, info.Size())
		if err := merger.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func processRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				return value * 1024
			}
		}
	}
	return 0
}

func TestPersistedAnalysisCorrelationParity(t *testing.T) {
	candidates := []Candidate{
		{Verification: Confirmed, CredentialType: "password", Identity: "svc", Value: "same", Host: "h", Share: "s", Path: "one.ini", Evidence: []Evidence{{RuleID: "one", Path: "one.ini"}}},
		{Verification: Review, CredentialType: "password", Identity: "svc", Value: "same", Host: "h", Share: "s", Path: "two.ini", Evidence: []Evidence{{RuleID: "two", Path: "two.ini"}}},
		{Verification: Confirmed, CredentialType: "password", Identity: "other", Value: "same", Host: "h", Share: "s", Path: "other.ini"},
	}
	want := Correlate(candidates)
	analysis, err := NewPersistedAnalysis()
	if err != nil {
		t.Fatal(err)
	}
	defer analysis.Close()
	for _, candidate := range candidates {
		if err := analysis.Add(context.Background(), candidate); err != nil {
			t.Fatal(err)
		}
	}
	var got []Correlation
	if err := analysis.IterateCorrelations(context.Background(), func(correlation Correlation) error {
		got = append(got, correlation)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("persisted correlations=%+v want=%+v", got, want)
	}
}

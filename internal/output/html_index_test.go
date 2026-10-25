package output

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"

	"snablr/internal/scanner"
)

func iteratorFromFindings(findings []scanner.Finding) reportFindingIterator {
	return func(ctx context.Context, visit func(scanner.Finding) error) error {
		for _, finding := range findings {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(finding); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestHTMLReportIndexMatchesGroupingAndOrderingContracts(t *testing.T) {
	first := sampleFinding()
	second := first
	second.FilePath = "Policies/Backup/Groups.xml"
	second.Host = "fs02"
	second.Share = "Backups"
	third := first
	third.FilePath = "Policies/Alpha/Groups.xml"
	third.Actionable = false
	third.Correlated = false
	third.ConfidenceScore = 10
	supporting := sampleConfigOnlyFinding()
	findings := []scanner.Finding{first, second, third, supporting}

	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	primary, err := index.CategorySummaries(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(primary) != 1 || primary[0].Category != "credentials" || primary[0].Findings != 1 {
		t.Fatalf("primary summaries=%+v", primary)
	}
	supportingSummaries, err := index.CategorySummaries(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(supportingSummaries) != 1 {
		t.Fatalf("supporting summaries=%+v", supportingSummaries)
	}

	var groups []HTMLReportGroup
	if err := index.ForEachGroup(context.Background(), true, func(group HTMLReportGroup) error {
		groups = append(groups, group)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].DuplicateCount != 2 || groups[0].FindingCount != 3 {
		t.Fatalf("primary groups=%+v", groups)
	}
	canonical, err := index.Canonical(context.Background(), groups[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.FilePath != first.FilePath || !canonical.Actionable {
		t.Fatalf("canonical=%+v", canonical)
	}
	var duplicatePaths []string
	if err := index.ForEachDuplicate(context.Background(), groups[0].Key, func(finding scanner.Finding) error {
		duplicatePaths = append(duplicatePaths, finding.FilePath)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(duplicatePaths, []string{third.FilePath, second.FilePath}) {
		t.Fatalf("duplicate paths=%v", duplicatePaths)
	}
	legacy := groupDuplicateReportFindings(findings)
	if len(legacy) != 2 || legacy[0].Canonical.FilePath != canonical.FilePath || len(legacy[0].Duplicates) != len(duplicatePaths) {
		t.Fatalf("index diverged from existing grouping: legacy=%+v", legacy)
	}
	anchorGroup, ok, err := index.CredentialAnchor(context.Background(), findingAnchor(first))
	if err != nil || !ok || anchorGroup != groups[0].Key {
		t.Fatalf("credential anchor lookup=(%q,%t), want %q", anchorGroup, ok, groups[0].Key)
	}
}

func TestHTMLReportIndexResolvesCredentialProvenanceToCanonicalAnchor(t *testing.T) {
	finding := sampleFinding()
	duplicate := finding
	duplicate.FilePath = "other/duplicate.ini"
	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings([]scanner.Finding{finding, duplicate}))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	anchor, ok, err := index.CredentialAnchorForProvenance(context.Background(), duplicate.Host, duplicate.Share, duplicate.FilePath)
	if err != nil || !ok || anchor != findingAnchor(finding) {
		t.Fatalf("provenance anchor=(%q,%t), want %q", anchor, ok, findingAnchor(finding))
	}
	other, ok, err := index.CredentialAnchorForProvenance(context.Background(), "other-host", duplicate.Share, duplicate.FilePath)
	if err != nil || ok || other != "" {
		t.Fatalf("unrelated provenance anchor=(%q,%t)", other, ok)
	}
}

func TestHTMLReportIndexHandlesLargeGroupsWithoutGoAccumulation(t *testing.T) {
	base := sampleFinding()
	findings := make([]scanner.Finding, 0, 10001)
	for n := 0; n < 10001; n++ {
		finding := base
		finding.FilePath = fmt.Sprintf("evidence/%08d/finding.txt", n)
		finding.Host = fmt.Sprintf("host-%02d", n%13)
		finding.Share = "share"
		findings = append(findings, finding)
	}
	index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if info, statErr := os.Stat(index.DiskPath()); statErr == nil {
		t.Logf("10,001-observation index disk size=%d bytes", info.Size())
	}
	var group HTMLReportGroup
	if err := index.ForEachGroup(context.Background(), true, func(candidate HTMLReportGroup) error {
		group = candidate
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if group.FindingCount != 10001 || group.DuplicateCount != 10000 {
		t.Fatalf("large group=%+v", group)
	}
	count := 0
	if err := index.ForEachDuplicate(context.Background(), group.Key, func(scanner.Finding) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 10000 {
		t.Fatalf("streamed duplicate count=%d", count)
	}
	runtime.ReadMemStats(&after)
	t.Logf("index heap alloc before=%d after=%d bytes", before.HeapAlloc, after.HeapAlloc)
}

func TestHTMLReportIndexHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := BuildHTMLReportIndex(ctx, iteratorFromFindings([]scanner.Finding{sampleFinding()}))
	if err == nil {
		t.Fatal("expected cancelled index preparation to fail")
	}
}

func BenchmarkHTMLReportIndexPreparation10K(b *testing.B) {
	base := sampleFinding()
	findings := make([]scanner.Finding, 10000)
	for n := range findings {
		findings[n] = base
		findings[n].FilePath = fmt.Sprintf("bench/%08d/finding.txt", n)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		index, err := BuildHTMLReportIndex(context.Background(), iteratorFromFindings(findings))
		if err != nil {
			b.Fatal(err)
		}
		if err := index.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

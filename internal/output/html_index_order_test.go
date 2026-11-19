package output

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"snablr/internal/scanner"
)

// htmlIndexLayout describes what an index shows: groups in order, each with
// its canonical card and duplicate locations, plus the access paths and the
// card a credential's source path links to.
func htmlIndexLayout(t *testing.T, findings []scanner.Finding) string {
	t.Helper()
	ctx := context.Background()
	index, err := BuildHTMLReportIndex(ctx, iteratorFromFindings(findings))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	var layout strings.Builder
	for _, primary := range []bool{true, false} {
		if err := index.ForEachGroup(ctx, primary, func(group HTMLReportGroup) error {
			canonical, err := index.Canonical(ctx, group.Key)
			if err != nil {
				return err
			}
			fmt.Fprintf(&layout, "group %s %s %s:", canonical.FilePath, canonical.RuleID, canonical.Match)
			if err := index.ForEachDuplicate(ctx, group.Key, func(f scanner.Finding) error {
				fmt.Fprintf(&layout, " %s/%s", f.FilePath, f.Match)
				return nil
			}); err != nil {
				return err
			}
			layout.WriteString("\n")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := index.TopAccessPaths(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&layout, "access paths %+v\n", paths)
	anchor, _, err := index.CredentialAnchorForProvenance(ctx, "fs01", "Share", "Configs/same.ini")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&layout, "anchor %s\n", anchor)
	return layout.String()
}

// The HTML report shows the same cards, in the same order, whatever order
// the scan's workers stored the findings in.
func TestHTMLReportIndexLayoutDoesNotDependOnStorageOrder(t *testing.T) {
	var findings []scanner.Finding
	for i := 0; i < 6; i++ {
		f := sampleFinding()
		f.Host, f.Share = "fs01", "Share"
		f.FilePath = fmt.Sprintf("Configs/Copy-%d/app.ini", i)
		findings = append(findings, f)
	}
	for _, rule := range []string{"content.synthetic_password", "content.synthetic_note", "content.synthetic_secret"} {
		f := sampleFinding()
		f.Host, f.Share, f.FilePath, f.RuleID = "fs01", "Share", "Configs/same.ini", rule
		f.Match = "match for " + rule
		findings = append(findings, f)
	}
	reversed := make([]scanner.Finding, len(findings))
	for i, f := range findings {
		reversed[len(findings)-1-i] = f
	}
	rotated := append(append([]scanner.Finding{}, findings[4:]...), findings[:4]...)
	want := htmlIndexLayout(t, findings)
	for name, order := range map[string][]scanner.Finding{"reversed": reversed, "rotated": rotated} {
		if got := htmlIndexLayout(t, order); got != want {
			t.Fatalf("%s storage order changes the report:\n%s\nvs\n%s", name, want, got)
		}
	}
}

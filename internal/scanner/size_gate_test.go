package scanner

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"snablr/internal/artifactbundle"
	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
	"snablr/internal/rules"
	"snablr/internal/systemkey"
	"snablr/pkg/logx"
)

// Real SYSTEM hives and NTDS databases are routinely larger than the general
// file size limit. Loose artifacts within their own limits must still reach
// the offline bundle path instead of being dropped by the general size gate.
func TestLooseHivesLargerThanGeneralLimitStillReachBundlePath(t *testing.T) {
	current := uint32(1)
	systemBytes := testfixture.Build(testfixture.Spec{
		Current: &current, IncludeSelect: true, IncludeCurrent: true,
		IncludeControl: true, IncludeLSA: true,
		Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"},
	})
	systemHive, err := registryhive.Open(bytes.NewReader(systemBytes), int64(len(systemBytes)), registryhive.Options{})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := systemkey.Derive(systemHive)
	if err != nil {
		t.Fatal(err)
	}
	var hash [16]byte
	samBytes := testfixture.BuildSAM(testfixture.SAMSpec{BootKey: boot.BootKey, KeyRevision: 1, IncludeDomain: true,
		Accounts: []testfixture.SAMAccount{{RID: 500, Username: "localadmin", NTHash: hash, HashRevision: 1}}})

	coordinator := artifactbundle.New(artifactbundle.Options{})
	defer coordinator.Close()
	generalLimit := int64(1024)
	if int64(len(systemBytes)) <= generalLimit || int64(len(samBytes)) <= generalLimit {
		t.Fatalf("fixture hives must exceed the general limit: system=%d sam=%d", len(systemBytes), len(samBytes))
	}
	engine := NewEngine(Options{BundleCoordinator: coordinator, MaxFileSizeBytes: generalLimit, SAMMaxBytes: 32 << 20, SYSTEMMaxBytes: 64 << 20}, &rules.Manager{}, nil, logx.New("error"))

	samMeta := FileMetadata{Host: "host", Share: "share", FilePath: "/backup/SAM", Name: "SAM", Size: int64(len(samBytes))}
	systemMeta := FileMetadata{Host: "host", Share: "share", FilePath: "/backup/SYSTEM", Name: "SYSTEM", Size: int64(len(systemBytes))}
	if !engine.NeedsContent(samMeta) || !engine.NeedsContent(systemMeta) {
		t.Fatal("loose hives above the general limit were not read")
	}
	engine.EvaluateContext(context.Background(), samMeta, samBytes)
	systemEval := engine.EvaluateContext(context.Background(), systemMeta, systemBytes)
	for _, finding := range systemEval.Findings {
		if finding.RuleID == samBundleFindingRuleID {
			return
		}
	}
	t.Fatalf("SAM/SYSTEM bundle was not parsed for hives above the general limit: %v", ruleIDs(systemEval.Findings))
}

// Files above the size limit are not read, but name-based evidence must not
// be dropped, and such files must not be left needing content.
func TestOversizedFilesKeepNameBasedFindingsWithoutReading(t *testing.T) {
	engine := NewEngine(Options{MaxFileSizeBytes: 10 << 20, MaxReadBytes: 10 << 20}, loadOfficeRules(t), nil, logx.New("error"))
	meta := FileMetadata{FilePath: "Backups/Domain/NTDS.dit.bak", Name: "NTDS.dit.bak", Extension: ".bak", Size: 900 << 20}
	if engine.NeedsContent(meta) {
		t.Fatal("oversized binary file would be read")
	}
	evaluation := engine.EvaluateContext(context.Background(), meta, nil)
	if !evaluation.Skipped || evaluation.NeedContent {
		t.Fatalf("oversized file should be skipped without needing content: skipped=%v needContent=%v", evaluation.Skipped, evaluation.NeedContent)
	}
	if !hasRuleID(evaluation.Findings, "filename.ad_database_backup_artifacts") {
		t.Fatalf("name-based finding dropped for oversized file: %v", ruleIDs(evaluation.Findings))
	}
}

// Oversized text files are inspected by their leading bytes; findings are
// tagged so reviewers know the rest was not read.
func TestOversizedTextFilesAreInspectedByPrefix(t *testing.T) {
	limit := int64(4096)
	engine := NewEngine(Options{MaxFileSizeBytes: limit, MaxReadBytes: limit}, loadOfficeRules(t), nil, logx.New("error"))
	head := "-- synthetic export\nusername=svc_synthetic\npassword=Synthetic-Prefix-61!\n"
	content := []byte(head + strings.Repeat("INSERT INTO t VALUES (1);\n", 1000))
	meta := FileMetadata{FilePath: "Exports/database-dump.sql", Name: "database-dump.sql", Extension: ".sql", Size: int64(len(content))}
	if got := engine.PrefixReadLimit(meta); got != limit {
		t.Fatalf("prefix read limit=%d, want %d", got, limit)
	}
	if !engine.NeedsContent(meta) {
		t.Fatal("oversized text file was not scheduled for a prefix read")
	}
	evaluation := engine.EvaluateContext(context.Background(), meta, content[:limit])
	finding, ok := confirmedCredentialFinding(evaluation.Findings)
	if !ok {
		t.Fatalf("credential in the prefix of an oversized file was missed: %v", ruleIDs(evaluation.Findings))
	}
	tagged := false
	for _, tag := range finding.Tags {
		tagged = tagged || tag == PrefixOnlyTag
	}
	if !tagged {
		t.Fatalf("prefix finding lacks %s tag: %v", PrefixOnlyTag, finding.Tags)
	}

	binary := FileMetadata{FilePath: "Exports/database.mdf", Name: "database.mdf", Extension: ".mdf", Size: int64(len(content))}
	if engine.PrefixReadLimit(binary) != 0 {
		t.Fatal("binary formats must not be prefix-read")
	}
}

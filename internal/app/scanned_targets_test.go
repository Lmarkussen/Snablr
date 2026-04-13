package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/discovery"
	"snablr/internal/planner"
)

func TestBuildScannedTargetRecordsIncludesReachabilityAndScanState(t *testing.T) {
	t.Parallel()

	records := buildScannedTargetRecords(discovery.PipelineResult{
		AllTargets: []discovery.Target{
			{Input: "fs01.example.local", Hostname: "fs01.example.local", IP: "10.0.0.10", Reachable445: true, Source: "ldap"},
			{Input: "fs02.example.local", Hostname: "fs02.example.local", IP: "10.0.0.11", Reachable445: false, Source: "ldap"},
		},
	}, []planner.PlannedTarget{
		{Host: "fs01.example.local", Source: "ldap"},
	})

	if len(records) != 2 {
		t.Fatalf("expected 2 target records, got %#v", records)
	}
	if !records[0].Reachable || !records[0].Scanned || records[0].SkipReason != "" {
		t.Fatalf("expected reachable planned host to be marked scanned, got %#v", records[0])
	}
	if records[1].Reachable || records[1].Scanned || records[1].SkipReason != "unreachable" {
		t.Fatalf("expected unreachable host to be marked skipped, got %#v", records[1])
	}
}

func TestWriteScannedTargetsWritesReadableAuditFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "scanned_targets.txt")

	err := writeScannedTargets(path, discovery.PipelineResult{
		Stats: discovery.TargetStats{
			Loaded:    3,
			Unique:    2,
			Reachable: 1,
			Skipped:   2,
		},
		AllTargets: []discovery.Target{
			{Input: "fs01.example.local", Hostname: "fs01.example.local", IP: "10.0.0.10", Reachable445: true, Source: "ldap"},
			{Input: "10.0.0.12", Hostname: "10.0.0.12", IP: "10.0.0.12", Reachable445: false, Source: "dfs"},
		},
	}, []planner.PlannedTarget{
		{Host: "fs01.example.local", Source: "ldap"},
	})
	if err != nil {
		t.Fatalf("writeScannedTargets returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"# Snablr scanned target audit",
		"# Targets loaded: 3",
		"# Unique targets: 2",
		"# Reachable SMB hosts: 1",
		"ldap\tfs01.example.local\t10.0.0.10\tyes\tyes\t-\tfs01.example.local",
		"dfs\t10.0.0.12\t10.0.0.12\tno\tno\tunreachable\t10.0.0.12",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected audit file to contain %q, got:\n%s", want, text)
		}
	}
}

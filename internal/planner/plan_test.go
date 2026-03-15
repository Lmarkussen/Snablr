package planner

import (
	"strings"
	"testing"
)

func TestPlanSharesPrioritizesADShares(t *testing.T) {
	t.Parallel()

	planned := PlanShares([]ShareInput{
		{Host: "dc01", Share: "Public", PrioritizeADShares: true},
		{Host: "dc01", Share: "NETLOGON", PrioritizeADShares: true},
		{Host: "dc01", Share: "SYSVOL", PrioritizeADShares: true},
	}, FilterOptions{})

	if len(planned) != 3 {
		t.Fatalf("expected 3 planned shares, got %d", len(planned))
	}
	if planned[0].Share != "SYSVOL" || planned[1].Share != "NETLOGON" {
		t.Fatalf("unexpected share order: %#v", planned)
	}
	if !strings.Contains(planned[0].Reason, "SYSVOL") {
		t.Fatalf("expected SYSVOL reason, got %q", planned[0].Reason)
	}
}

func TestPlanFilesBoostsPoliciesAndExtensions(t *testing.T) {
	t.Parallel()

	planned := PlanFiles([]FileInput{
		{
			Host:               "dc01",
			Share:              "SYSVOL",
			Path:               "Policies/Groups.xml",
			Extension:          ".xml",
			Source:             "ldap",
			PrioritizeADShares: true,
		},
		{
			Host:               "dc01",
			Share:              "Public",
			Path:               "notes/readme.txt",
			Extension:          ".txt",
			Source:             "ldap",
			PrioritizeADShares: true,
		},
	}, FilterOptions{})

	if len(planned) != 2 {
		t.Fatalf("expected 2 planned files, got %d", len(planned))
	}
	if planned[0].Path != "Policies/Groups.xml" {
		t.Fatalf("unexpected file order: %#v", planned)
	}
	if !strings.Contains(planned[0].Reason, "Policies") {
		t.Fatalf("expected Policies reason, got %q", planned[0].Reason)
	}
}

func TestPlanFiltersLimitSharesAndPaths(t *testing.T) {
	t.Parallel()

	sharePlan := PlanShares([]ShareInput{
		{Host: "fs01", Share: "Finance"},
		{Host: "fs01", Share: "Backups"},
	}, FilterOptions{
		IncludeShares: []string{"Finance"},
		ExcludeShares: []string{"Backups"},
	})
	if len(sharePlan) != 1 || sharePlan[0].Share != "Finance" {
		t.Fatalf("unexpected filtered share plan: %#v", sharePlan)
	}

	filePlan := PlanFiles([]FileInput{
		{Host: "dc01", Share: "SYSVOL", Path: "Policies/Groups.xml", Extension: ".xml"},
		{Host: "dc01", Share: "SYSVOL", Path: "Policies/Deep/Nested/file.xml", Extension: ".xml"},
		{Host: "dc01", Share: "SYSVOL", Path: "Scripts/logon.ps1", Extension: ".ps1"},
	}, FilterOptions{
		IncludePaths: []string{"Policies/"},
		ExcludePaths: []string{"Policies/Deep"},
		MaxDepth:     1,
	})
	if len(filePlan) != 1 || filePlan[0].Path != "Policies/Groups.xml" {
		t.Fatalf("unexpected filtered file plan: %#v", filePlan)
	}
}

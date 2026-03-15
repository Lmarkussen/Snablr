package diff

import (
	"testing"

	"snablr/internal/scanner"
)

func TestCompareCategorizesFindings(t *testing.T) {
	t.Parallel()

	previous := []scanner.Finding{
		{
			RuleID:   "rule.same",
			RuleName: "Same",
			Severity: "high",
			Category: "credentials",
			Host:     "fs01",
			Share:    "finance",
			FilePath: "config/app.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.changed",
			RuleName: "Changed",
			Severity: "medium",
			Category: "credentials",
			Host:     "fs01",
			Share:    "finance",
			FilePath: "config/db.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.removed",
			RuleName: "Removed",
			Severity: "low",
			Category: "configuration",
			Host:     "fs01",
			Share:    "finance",
			FilePath: "config/old.conf",
			Match:    "legacy",
		},
	}

	current := []scanner.Finding{
		previous[0],
		{
			RuleID:   "rule.changed",
			RuleName: "Changed",
			Severity: "high",
			Category: "credentials",
			Host:     "fs01",
			Share:    "finance",
			FilePath: "config/db.conf",
			Match:    "password = placeholder",
		},
		{
			RuleID:   "rule.new",
			RuleName: "New",
			Severity: "critical",
			Category: "credentials",
			Host:     "fs02",
			Share:    "hr",
			FilePath: "Policies/Groups.xml",
			Match:    "cpassword",
		},
	}

	result := Compare(previous, current)
	summary := result.Summary()

	if summary.New != 1 || summary.Removed != 1 || summary.Changed != 1 || summary.Unchanged != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if len(result.Changed[0].ChangedFields) == 0 || result.Changed[0].ChangedFields[0] != "severity" {
		t.Fatalf("expected severity change, got %#v", result.Changed[0])
	}
}

func TestFingerprintNormalizesIdentity(t *testing.T) {
	t.Parallel()

	left := Fingerprint(scanner.Finding{
		RuleID:   "RULE.ID",
		Host:     "FS01",
		Share:    "Finance",
		FilePath: `Config\App.conf`,
		Match:    "Password = Placeholder",
	})
	right := Fingerprint(scanner.Finding{
		RuleID:   "rule.id",
		Host:     "fs01",
		Share:    "finance",
		FilePath: "config/app.conf",
		Match:    "password = placeholder",
	})

	if left != right {
		t.Fatalf("expected normalized fingerprints to match: %#v != %#v", left, right)
	}
}

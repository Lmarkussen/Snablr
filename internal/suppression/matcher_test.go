package suppression

import (
	"testing"

	"snablr/internal/config"
	"snablr/internal/scanner"
)

func sampleFinding() scanner.Finding {
	return scanner.Finding{
		RuleID:         "content.password_assignment_indicators",
		MatchedRuleIDs: []string{"content.password_assignment_indicators"},
		Category:       "credentials",
		Host:           "fs01",
		Share:          "Finance",
		FilePath:       "Apps/Payroll/appsettings.json",
		Match:          "db.password=CorrectHorseBatteryStaple!",
		Tags:           []string{"credentials", "app:payroll"},
	}
}

func TestMatcherExactPath(t *testing.T) {
	t.Parallel()

	matcher := New([]config.SuppressionRule{{
		ID:         "suppress-payroll-config",
		Reason:     "known benign payroll config",
		Enabled:    true,
		ExactPaths: []string{"Apps/Payroll/appsettings.json"},
	}})
	match, ok := matcher.Match(sampleFinding())
	if !ok || match.SuppressionID != "suppress-payroll-config" {
		t.Fatalf("expected exact path match, got ok=%t match=%#v", ok, match)
	}
}

func TestMatcherPathPrefixAndRuleScope(t *testing.T) {
	t.Parallel()

	matcher := New([]config.SuppressionRule{{
		ID:           "suppress-payroll-tree",
		Reason:       "known payroll deployment tree",
		Enabled:      true,
		PathPrefixes: []string{"Apps/Payroll/"},
		RuleIDs:      []string{"content.password_assignment_indicators"},
	}})
	if _, ok := matcher.Match(sampleFinding()); !ok {
		t.Fatal("expected path prefix and rule scoped suppression to match")
	}
}

func TestMatcherFingerprint(t *testing.T) {
	t.Parallel()

	finding := sampleFinding()
	fp := FingerprintString(finding)
	matcher := New([]config.SuppressionRule{{
		ID:           "suppress-fingerprint",
		Reason:       "reviewed specific finding",
		Enabled:      true,
		Fingerprints: []string{fp},
	}})
	if _, ok := matcher.Match(finding); !ok {
		t.Fatal("expected fingerprint suppression to match")
	}
}

func TestMatcherScopedSuppressionDoesNotSpillOver(t *testing.T) {
	t.Parallel()

	matcher := New([]config.SuppressionRule{{
		ID:        "suppress-finance-only",
		Reason:    "finance-only allowlist",
		Enabled:   true,
		Shares:    []string{"Finance"},
		RuleIDs:   []string{"content.password_assignment_indicators"},
		Tags:      []string{"app:payroll"},
	}})
	if _, ok := matcher.Match(sampleFinding()); !ok {
		t.Fatal("expected scoped suppression to match original finding")
	}
	other := sampleFinding()
	other.Share = "HR"
	if _, ok := matcher.Match(other); ok {
		t.Fatalf("expected scoped suppression not to spill over to other share, got match for %#v", other)
	}
}

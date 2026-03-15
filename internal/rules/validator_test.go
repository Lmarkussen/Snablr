package rules

import (
	"strings"
	"testing"
)

func TestValidateRuleFilesRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		files     []RuleFile
		wantIssue string
	}{
		{
			name: "bad regex",
			files: []RuleFile{{
				Version:    1,
				SourceFile: "bad-regex.yml",
				Rules: []Rule{{
					ID:          "content.bad_regex",
					Name:        "Bad Regex",
					Description: "bad regex",
					Type:        RuleTypeContent,
					Pattern:     "(",
					Severity:    SeverityHigh,
					Category:    "credentials",
					Action:      ActionReport,
					Enabled:     true,
				}},
			}},
			wantIssue: "bad regex pattern",
		},
		{
			name: "duplicate id",
			files: []RuleFile{
				{
					Version:    1,
					SourceFile: "one.yml",
					Rules: []Rule{{
						ID:          "filename.dup",
						Name:        "Dup One",
						Description: "dup one",
						Type:        RuleTypeFilename,
						Pattern:     "one",
						Severity:    SeverityLow,
						Category:    "configuration",
						Action:      ActionReport,
						Enabled:     true,
					}},
				},
				{
					Version:    1,
					SourceFile: "two.yml",
					Rules: []Rule{{
						ID:          "filename.dup",
						Name:        "Dup Two",
						Description: "dup two",
						Type:        RuleTypeFilename,
						Pattern:     "two",
						Severity:    SeverityLow,
						Category:    "configuration",
						Action:      ActionReport,
						Enabled:     true,
					}},
				},
			},
			wantIssue: "duplicate id",
		},
		{
			name: "invalid severity",
			files: []RuleFile{{
				Version:    1,
				SourceFile: "bad-severity.yml",
				Rules: []Rule{{
					ID:          "filename.bad_severity",
					Name:        "Bad Severity",
					Description: "bad severity",
					Type:        RuleTypeFilename,
					Pattern:     "bad",
					Severity:    Severity("severe"),
					Category:    "configuration",
					Action:      ActionReport,
					Enabled:     true,
				}},
			}},
			wantIssue: "invalid severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, issues := ValidateRuleFiles(tt.files)
			if len(issues) == 0 {
				t.Fatalf("expected validation issues")
			}

			found := false
			for _, issue := range issues {
				if strings.Contains(issue.Message, tt.wantIssue) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected issue containing %q, got %#v", tt.wantIssue, issues)
			}
		})
	}
}

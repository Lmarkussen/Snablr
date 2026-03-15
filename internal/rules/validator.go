package rules

import (
	"fmt"
	"regexp"
	"strings"
)

func ValidateRuleFiles(files []RuleFile) ([]Rule, []ValidationIssue) {
	var (
		validRules []Rule
		issues     []ValidationIssue
		seen       = make(map[string]string)
	)

	for _, ruleFile := range files {
		if ruleFile.Version != 1 {
			issues = append(issues, ValidationIssue{
				File:    ruleFile.SourceFile,
				Message: fmt.Sprintf("unsupported version %d", ruleFile.Version),
			})
			continue
		}

		for _, rule := range ruleFile.Rules {
			ruleCopy := rule
			ruleIssues := validateRule(&ruleCopy)
			if len(ruleIssues) > 0 {
				issues = append(issues, ruleIssues...)
				continue
			}

			if firstFile, exists := seen[ruleCopy.ID]; exists {
				issues = append(issues, ValidationIssue{
					File:    ruleCopy.SourceFile,
					RuleID:  ruleCopy.ID,
					Message: fmt.Sprintf("duplicate id already loaded from %s", firstFile),
				})
				continue
			}
			seen[ruleCopy.ID] = ruleCopy.SourceFile

			validRules = append(validRules, ruleCopy)
		}
	}

	return validRules, issues
}

func validateRule(rule *Rule) []ValidationIssue {
	var issues []ValidationIssue

	if strings.TrimSpace(rule.ID) == "" {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, Message: "missing id"})
	}
	if len(rule.unknown) > 0 {
		issues = append(issues, ValidationIssue{
			File:    rule.SourceFile,
			RuleID:  rule.ID,
			Message: "rule contains unsupported fields and was rejected",
		})
	}
	if strings.TrimSpace(rule.Name) == "" {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: "missing name"})
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: "missing pattern"})
	}
	if strings.TrimSpace(rule.Category) == "" {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: "missing category"})
	}
	if !validRuleType(rule.Type) {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: fmt.Sprintf("invalid type %q", rule.Type)})
	}
	if !validSeverity(rule.Severity) {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: fmt.Sprintf("invalid severity %q", rule.Severity)})
	}
	if !validConfidence(rule.Confidence) {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: fmt.Sprintf("invalid confidence %q", rule.Confidence)})
	}
	if !validAction(rule.Action) {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: fmt.Sprintf("invalid action %q", rule.Action)})
	}
	if rule.MaxFileSize < 0 {
		issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: "max_file_size cannot be negative"})
	}

	for _, ext := range rule.FileExtensions {
		if strings.TrimSpace(ext) == "" {
			issues = append(issues, ValidationIssue{File: rule.SourceFile, RuleID: rule.ID, Message: "file_extensions cannot contain empty values"})
			break
		}
	}

	if len(issues) > 0 {
		return issues
	}

	expr := rule.Pattern
	if !rule.CaseSensitive {
		expr = "(?i)" + expr
	}

	compiled, err := regexp.Compile(expr)
	if err != nil {
		issues = append(issues, ValidationIssue{
			File:    rule.SourceFile,
			RuleID:  rule.ID,
			Message: fmt.Sprintf("bad regex pattern %q: %v", rule.Pattern, err),
		})
		return issues
	}
	rule.compiled = compiled

	return nil
}

func validRuleType(ruleType RuleType) bool {
	switch ruleType {
	case RuleTypeContent, RuleTypeFilename, RuleTypeExtension:
		return true
	default:
		return false
	}
}

func validSeverity(severity Severity) bool {
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validAction(action RuleAction) bool {
	switch action {
	case ActionReport, ActionSkip, ActionPrioritize:
		return true
	default:
		return false
	}
}

func validConfidence(confidence Confidence) bool {
	switch confidence {
	case "", ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}

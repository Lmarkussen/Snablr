package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type TestMatch struct {
	RuleID   string
	RuleName string
	File     string
	Match    string
	Snippet  string
}

type TestResult struct {
	File    string
	Skipped bool
	Matches []TestMatch
}

type TestSummary struct {
	FilesScanned int
	FilesMatched int
	FilesSkipped int
	Matches      []TestMatch
}

func TestRuleFile(ruleFilePath, inputFile string) (TestSummary, []ValidationIssue, error) {
	ruleFile, issues, err := loadRuleFile(ruleFilePath)
	if err != nil {
		return TestSummary{}, issues, err
	}

	manager, validationIssues := newTestManager([]RuleFile{ruleFile})
	issues = append(issues, validationIssues...)
	if len(validationIssues) > 0 {
		return TestSummary{}, issues, nil
	}

	result, err := testInputFile(manager, inputFile)
	if err != nil {
		return TestSummary{}, issues, err
	}

	summary := TestSummary{
		FilesScanned: 1,
		Matches:      append([]TestMatch{}, result.Matches...),
	}
	if result.Skipped {
		summary.FilesSkipped = 1
	}
	if len(result.Matches) > 0 {
		summary.FilesMatched = 1
	}
	return summary, issues, nil
}

func TestRuleDirectory(rulesDir, fixturesDir string) (TestSummary, []ValidationIssue, error) {
	files, issues, err := LoadRuleFiles([]string{rulesDir})
	if err != nil {
		return TestSummary{}, issues, err
	}

	manager, validationIssues := newTestManager(files)
	issues = append(issues, validationIssues...)
	if len(validationIssues) > 0 {
		return TestSummary{}, issues, nil
	}

	summary := TestSummary{}
	err = filepath.WalkDir(fixturesDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		result, err := testInputFile(manager, path)
		if err != nil {
			return err
		}

		summary.FilesScanned++
		if result.Skipped {
			summary.FilesSkipped++
		}
		if len(result.Matches) > 0 {
			summary.FilesMatched++
			summary.Matches = append(summary.Matches, result.Matches...)
		}
		return nil
	})
	if err != nil {
		return summary, issues, err
	}

	sort.Slice(summary.Matches, func(i, j int) bool {
		if summary.Matches[i].File == summary.Matches[j].File {
			return summary.Matches[i].RuleID < summary.Matches[j].RuleID
		}
		return summary.Matches[i].File < summary.Matches[j].File
	})
	return summary, issues, nil
}

func newTestManager(files []RuleFile) (*Manager, []ValidationIssue) {
	validRules, issues := ValidateRuleFiles(files)
	if len(issues) > 0 {
		return nil, issues
	}

	enabledRules := filterEnabledRules(validRules, ManagerOptions{})
	manager := &Manager{
		files:        files,
		allRules:     validRules,
		enabledRules: enabledRules,
	}

	for _, rule := range enabledRules {
		switch rule.Type {
		case RuleTypeContent:
			manager.contentRules = append(manager.contentRules, rule)
		case RuleTypeFilename:
			manager.filenameRules = append(manager.filenameRules, rule)
		case RuleTypeExtension:
			manager.extensionRules = append(manager.extensionRules, rule)
		}
		if rule.Action == ActionSkip {
			manager.skipRules = append(manager.skipRules, rule)
		}
	}

	return manager, nil
}

func testInputFile(manager *Manager, inputFile string) (TestResult, error) {
	info, err := os.Stat(inputFile)
	if err != nil {
		return TestResult{}, fmt.Errorf("stat input file %s: %w", inputFile, err)
	}
	if info.IsDir() {
		return TestResult{}, fmt.Errorf("%s is a directory", inputFile)
	}

	content, err := os.ReadFile(inputFile)
	if err != nil {
		return TestResult{}, fmt.Errorf("read input file %s: %w", inputFile, err)
	}

	candidate := Candidate{
		Path:      NormalizePath(inputFile),
		Name:      filepath.Base(inputFile),
		Extension: strings.ToLower(filepath.Ext(inputFile)),
		Content:   string(content),
		Size:      info.Size(),
		IsDir:     false,
	}

	if skipped, _ := manager.ShouldExclude(candidate); skipped {
		return TestResult{File: inputFile, Skipped: true}, nil
	}

	results := append(manager.MatchFilename(candidate), manager.MatchContent(candidate)...)
	matches := make([]TestMatch, 0, len(results))
	for _, result := range results {
		match := ""
		if len(result.Matched) > 0 {
			match = result.Matched[0]
		}
		matches = append(matches, TestMatch{
			RuleID:   result.Rule.ID,
			RuleName: result.Rule.Name,
			File:     inputFile,
			Match:    match,
			Snippet:  buildSnippet(result.Rule, candidate.Content, match),
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].File == matches[j].File {
			return matches[i].RuleID < matches[j].RuleID
		}
		return matches[i].File < matches[j].File
	})
	return TestResult{File: inputFile, Matches: matches}, nil
}

func buildSnippet(rule Rule, content string, match string) string {
	if rule.Type != RuleTypeContent {
		return ""
	}
	if content == "" {
		return ""
	}
	if match == "" {
		return truncateForSnippet(content, 120)
	}

	expr := rule.Pattern
	if !rule.CaseSensitive {
		expr = "(?i)" + expr
	}
	rx, err := regexp.Compile(expr)
	if err != nil {
		return truncateForSnippet(content, 120)
	}

	loc := rx.FindStringIndex(content)
	if len(loc) != 2 {
		return truncateForSnippet(content, 120)
	}

	start := loc[0] - 40
	if start < 0 {
		start = 0
	}
	end := loc[1] + 40
	if end > len(content) {
		end = len(content)
	}
	return sanitizeSnippet(content[start:end])
}

func truncateForSnippet(content string, max int) string {
	if len(content) > max {
		content = content[:max]
	}
	return sanitizeSnippet(content)
}

func sanitizeSnippet(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.TrimSpace(value)
}

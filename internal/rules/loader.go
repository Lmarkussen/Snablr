package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ValidationIssue struct {
	File    string
	RuleID  string
	Message string
}

func (i ValidationIssue) Error() string {
	if i.RuleID == "" {
		return fmt.Sprintf("%s: %s", i.File, i.Message)
	}
	return fmt.Sprintf("%s: rule %s: %s", i.File, i.RuleID, i.Message)
}

func LoadManager(paths []string, failOnInvalid bool, opts ManagerOptions) (*Manager, []error, error) {
	manager := &Manager{
		paths: paths,
		opts:  opts,
	}

	issues, err := manager.Reload()
	if err != nil {
		return nil, toErrorSlice(issues), err
	}
	if failOnInvalid && len(issues) > 0 {
		return nil, toErrorSlice(issues), errors.Join(toErrorSlice(issues)...)
	}
	return manager, toErrorSlice(issues), nil
}

func LoadRuleFiles(paths []string) ([]RuleFile, []ValidationIssue, error) {
	var (
		files  []RuleFile
		issues []ValidationIssue
	)

	for _, root := range paths {
		if strings.TrimSpace(root) == "" {
			continue
		}

		info, err := os.Stat(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, nil, fmt.Errorf("stat %s: %w", root, err)
		}
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("%s is not a directory", root)
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				issues = append(issues, ValidationIssue{File: root, Message: walkErr.Error()})
				return nil
			}
			if d.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}

			ruleFile, fileIssues, err := loadRuleFile(path)
			issues = append(issues, fileIssues...)
			if err != nil {
				issues = append(issues, ValidationIssue{File: path, Message: err.Error()})
				return nil
			}
			files = append(files, ruleFile)
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walk %s: %w", root, err)
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].SourceFile < files[j].SourceFile
	})

	return files, issues, nil
}

func loadRuleFile(path string) (RuleFile, []ValidationIssue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuleFile{}, nil, fmt.Errorf("read file: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return RuleFile{}, nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(root.Content) == 0 {
		return RuleFile{}, nil, fmt.Errorf("empty yaml document")
	}

	doc := root.Content[0]
	issues := warnUnknownKeys(path, "", doc, topLevelKeys)

	var raw struct {
		Version     int         `yaml:"version"`
		Name        string      `yaml:"name"`
		Description string      `yaml:"description"`
		Rules       []yaml.Node `yaml:"rules"`
	}
	if err := doc.Decode(&raw); err != nil {
		return RuleFile{}, issues, fmt.Errorf("decode rule file: %w", err)
	}

	ruleFile := RuleFile{
		Version:     raw.Version,
		Name:        raw.Name,
		Description: raw.Description,
		SourceFile:  path,
	}
	if ruleFile.Version == 0 {
		ruleFile.Version = 1
	}

	for idx, node := range raw.Rules {
		unknownFields := unknownKeys(&node, ruleKeys)
		ruleIssues := make([]ValidationIssue, 0, len(unknownFields))
		for _, field := range unknownFields {
			ruleIssues = append(ruleIssues, ValidationIssue{
				File:    path,
				Message: fmt.Sprintf("unsupported field %q", field),
			})
		}
		issues = append(issues, ruleIssues...)

		rule := Rule{
			Enabled:    true,
			Action:     ActionReport,
			Severity:   SeverityMedium,
			SourceFile: path,
			FileName:   filepath.Base(path),
			index:      idx,
		}
		if err := node.Decode(&rule); err != nil {
			issues = append(issues, ValidationIssue{
				File:    path,
				Message: fmt.Sprintf("decode rule at index %d: %v", idx, err),
			})
			continue
		}
		rule.SourceFile = path
		rule.FileName = filepath.Base(path)
		rule.index = idx
		rule.unknown = unknownFields
		ruleFile.Rules = append(ruleFile.Rules, rule)
	}

	return ruleFile, issues, nil
}

var topLevelKeys = map[string]struct{}{
	"version":     {},
	"name":        {},
	"description": {},
	"rules":       {},
}

var ruleKeys = map[string]struct{}{
	"id":              {},
	"name":            {},
	"description":     {},
	"type":            {},
	"pattern":         {},
	"case_sensitive":  {},
	"severity":        {},
	"confidence":      {},
	"explanation":     {},
	"remediation":     {},
	"tags":            {},
	"category":        {},
	"enabled":         {},
	"include_paths":   {},
	"exclude_paths":   {},
	"file_extensions": {},
	"max_file_size":   {},
	"action":          {},
}

func warnUnknownKeys(path, ruleID string, node *yaml.Node, allowed map[string]struct{}) []ValidationIssue {
	unknown := unknownKeys(node, allowed)
	issues := make([]ValidationIssue, 0, len(unknown))
	for _, field := range unknown {
		issues = append(issues, ValidationIssue{
			File:    path,
			RuleID:  ruleID,
			Message: fmt.Sprintf("unsupported field %q", field),
		})
	}
	return issues
}

func unknownKeys(node *yaml.Node, allowed map[string]struct{}) []string {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	fields := make([]string, 0)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		if _, ok := allowed[keyNode.Value]; ok {
			continue
		}
		fields = append(fields, keyNode.Value)
	}
	return fields
}

func toErrorSlice(issues []ValidationIssue) []error {
	errs := make([]error, 0, len(issues))
	for _, issue := range issues {
		errs = append(errs, issue)
	}
	return errs
}

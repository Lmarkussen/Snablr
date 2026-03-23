package sqliteinspect

type Options struct {
	Enabled            bool
	AutoDBMaxSize      int64
	AllowLargeDBs      bool
	MaxDBSize          int64
	MaxTables          int
	MaxRowsPerTable    int
	MaxCellBytes       int64
	MaxTotalBytes      int64
	MaxInterestingCols int
}

type Candidate struct {
	FilePath  string
	Name      string
	Extension string
	Size      int64
}

type Match struct {
	ID                  string
	Name                string
	Description         string
	RuleType            string
	SignalType          string
	Severity            string
	Confidence          string
	Category            string
	Match               string
	MatchedText         string
	MatchedTextRedacted string
	Snippet             string
	Context             string
	ContextRedacted     string
	LineNumber          int
	Explanation         string
	Remediation         string
	Tags                []string
	DatabaseTable       string
	DatabaseColumn      string
	DatabaseRowContext  string
	DatabaseFilePath    string
}

type Inspector struct {
	opts Options
}

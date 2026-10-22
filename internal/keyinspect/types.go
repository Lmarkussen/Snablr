package keyinspect

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
	Format              string
	Algorithm           string
	Status              string
	Encrypted           bool
	ValidationBasis     string
	ReviewReason        string
}

type Inspector struct{}

package dbinspect

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
}

type Inspector struct{}

type artifactDefinition struct {
	id          string
	name        string
	description string
	ecosystem   string
	match       string
}

type stringObservation struct {
	category    string
	severity    string
	confidence  string
	signalType  string
	id          string
	name        string
	description string
	explanation string
	remediation string
	match       string
	lineNumber  int
	tags        []string
}

type authFields struct {
	user       string
	password   string
	integrated bool
}

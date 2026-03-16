package eval

import (
	"time"

	"snablr/internal/benchmark"
	"snablr/internal/scanner"
)

type LabelsFile struct {
	Version      int           `json:"version" yaml:"version"`
	Name         string        `json:"name" yaml:"name"`
	Description  string        `json:"description" yaml:"description"`
	Expectations []Expectation `json:"expectations" yaml:"expectations"`
}

type Expectation struct {
	ID                string   `json:"id,omitempty" yaml:"id"`
	Path              string   `json:"path" yaml:"path"`
	Category          string   `json:"category" yaml:"category"`
	RuleIDs           []string `json:"rule_ids,omitempty" yaml:"rule_ids"`
	MinimumSeverity   string   `json:"minimum_severity,omitempty" yaml:"minimum_severity"`
	MinimumConfidence string   `json:"minimum_confidence,omitempty" yaml:"minimum_confidence"`
	Notes             string   `json:"notes,omitempty" yaml:"notes"`
}

type RuleCandidate struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type MatchedExpectation struct {
	Expectation Expectation     `json:"expectation"`
	Finding     scanner.Finding `json:"finding"`
	Warnings    []string        `json:"warnings,omitempty"`
}

type MissedExpectation struct {
	Expectation Expectation `json:"expectation"`
	Reason      string      `json:"reason"`
}

type NoisyFinding struct {
	Path     string          `json:"path"`
	Category string          `json:"category"`
	Finding  scanner.Finding `json:"finding"`
}

type DuplicateFinding struct {
	Path     string            `json:"path"`
	Category string            `json:"category"`
	Findings []scanner.Finding `json:"findings"`
}

type Summary struct {
	ExpectedTotal  int     `json:"expected_total"`
	MatchedTotal   int     `json:"matched_total"`
	MissedTotal    int     `json:"missed_total"`
	NoisyTotal     int     `json:"noisy_total"`
	DuplicateTotal int     `json:"duplicate_total"`
	WarningsTotal  int     `json:"warnings_total"`
	PrecisionLike  float64 `json:"precision_like"`
	RecallLike     float64 `json:"recall_like"`
}

type Report struct {
	Name                 string               `json:"name,omitempty"`
	Dataset              string               `json:"dataset"`
	Labels               string               `json:"labels"`
	StartedAt            time.Time            `json:"started_at"`
	EndedAt              time.Time            `json:"ended_at"`
	Benchmark            benchmark.Report     `json:"benchmark"`
	Summary              Summary              `json:"summary"`
	Matched              []MatchedExpectation `json:"matched,omitempty"`
	Missed               []MissedExpectation  `json:"missed,omitempty"`
	Noisy                []NoisyFinding       `json:"noisy,omitempty"`
	Duplicates           []DuplicateFinding   `json:"duplicates,omitempty"`
	NoisyRuleCandidates  []RuleCandidate      `json:"noisy_rule_candidates,omitempty"`
	MissedRuleCandidates []RuleCandidate      `json:"missed_rule_candidates,omitempty"`
}

package benchmark

import (
	"time"

	"snablr/internal/config"
	"snablr/internal/metrics"
	"snablr/internal/scanner"
)

type Config struct {
	Name           string               `json:"name" yaml:"name"`
	Dataset        string               `json:"dataset" yaml:"dataset"`
	SnablrConfig   string               `json:"snablr_config" yaml:"snablr_config"`
	RulesDirectory string               `json:"rules_directory" yaml:"rules_directory"`
	WorkerCount    int                  `json:"worker_count" yaml:"worker_count"`
	MaxFileSize    int64                `json:"max_file_size" yaml:"max_file_size"`
	MaxReadBytes   int64                `json:"max_read_bytes" yaml:"max_read_bytes"`
	SnippetBytes   int                  `json:"snippet_bytes" yaml:"snippet_bytes"`
	LogLevel       string               `json:"log_level" yaml:"log_level"`
	Archives       config.ArchiveConfig `json:"archives" yaml:"archives"`
	SQLite         config.SQLiteConfig  `json:"sqlite" yaml:"sqlite"`
}

type CountStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type Report struct {
	Name                   string            `json:"name,omitempty"`
	Dataset                string            `json:"dataset"`
	RulesDirectories       []string          `json:"rules_directories,omitempty"`
	StartedAt              time.Time         `json:"started_at"`
	EndedAt                time.Time         `json:"ended_at"`
	DurationMS             int64             `json:"duration_ms"`
	TimeToFirstFindingMS   int64             `json:"time_to_first_finding_ms,omitempty"`
	TimeToFirstFindingSet  bool              `json:"-"`
	Metrics                metrics.Snapshot  `json:"metrics"`
	GroupedFindings        int               `json:"grouped_findings"`
	HighConfidenceFindings int               `json:"high_confidence_findings"`
	FindingsByCategory     []CountStat       `json:"findings_by_category,omitempty"`
	FindingsBySeverity     []CountStat       `json:"findings_by_severity,omitempty"`
	FindingsByRule         []CountStat       `json:"findings_by_rule,omitempty"`
	Findings               []scanner.Finding `json:"findings,omitempty"`
}

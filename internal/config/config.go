package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	App    AppConfig    `yaml:"app"`
	Scan   ScanConfig   `yaml:"scan"`
	Rules  RulesConfig  `yaml:"rules"`
	Output OutputConfig `yaml:"output"`
}

type AppConfig struct {
	Name       string `yaml:"name"`
	LogLevel   string `yaml:"log_level"`
	BannerPath string `yaml:"banner_path"`
}

type ScanConfig struct {
	Targets                    []string `yaml:"targets"`
	TargetsFile                string   `yaml:"targets_file"`
	Username                   string   `yaml:"username"`
	Password                   string   `yaml:"password"`
	Share                      []string `yaml:"share"`
	ExcludeShare               []string `yaml:"exclude_share"`
	Path                       []string `yaml:"path"`
	ExcludePath                []string `yaml:"exclude_path"`
	MaxDepth                   int      `yaml:"max_depth"`
	WorkerCount                int      `yaml:"worker_count"`
	MaxFileSize                int64    `yaml:"max_file_size"`
	NoLDAP                     bool     `yaml:"no_ldap"`
	Domain                     string   `yaml:"domain"`
	DomainController           string   `yaml:"dc"`
	BaseDN                     string   `yaml:"base_dn"`
	DiscoverDFS                bool     `yaml:"discover_dfs"`
	PrioritizeADShares         bool     `yaml:"prioritize_ad_shares"`
	OnlyADShares               bool     `yaml:"only_ad_shares"`
	Baseline                   string   `yaml:"baseline"`
	MaxScanTime                string   `yaml:"max_scan_time"`
	CheckpointFile             string   `yaml:"checkpoint_file"`
	Resume                     bool     `yaml:"resume"`
	SkipReachabilityCheck      bool     `yaml:"skip_reachability_check"`
	ReachabilityTimeoutSeconds int      `yaml:"reachability_timeout_seconds"`
}

type RulesConfig struct {
	Directory     string `yaml:"rules_directory"`
	FailOnInvalid bool   `yaml:"fail_on_invalid"`
}

type OutputConfig struct {
	Format  string `yaml:"output_format"`
	JSONOut string `yaml:"json_out"`
	HTMLOut string `yaml:"html_out"`
	CSVOut  string `yaml:"csv_out"`
	MDOut   string `yaml:"md_out"`
	Pretty  bool   `yaml:"pretty"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		applyDefaults(&cfg)
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	applyDefaults(&cfg)
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.App.Name == "" {
		cfg.App.Name = "snablr"
	}
	if cfg.App.LogLevel == "" {
		cfg.App.LogLevel = "info"
	}
	if cfg.App.BannerPath == "" {
		cfg.App.BannerPath = "internal/ui/assets/snablr.txt"
	}
	if cfg.Scan.MaxFileSize <= 0 {
		cfg.Scan.MaxFileSize = 10 * 1024 * 1024
	}
	if cfg.Scan.ReachabilityTimeoutSeconds <= 0 {
		cfg.Scan.ReachabilityTimeoutSeconds = 3
	}
	if cfg.Output.Format == "" {
		cfg.Output.Format = "console"
	}
	if cfg.Output.JSONOut == "" {
		cfg.Output.JSONOut = "results.json"
	}
	if cfg.Output.HTMLOut == "" {
		cfg.Output.HTMLOut = "report.html"
	}
}

func (c Config) RulePaths() []string {
	if strings.TrimSpace(c.Rules.Directory) != "" {
		return []string{c.Rules.Directory}
	}
	return []string{"configs/rules/default", "configs/rules/custom"}
}

func (s ScanConfig) ReachabilityTimeout() time.Duration {
	timeout := s.ReachabilityTimeoutSeconds
	if timeout <= 0 {
		timeout = 3
	}
	return time.Duration(timeout) * time.Second
}

func (s ScanConfig) MaxScanDuration() (time.Duration, error) {
	value := strings.TrimSpace(s.MaxScanTime)
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse max_scan_time %q: %w", value, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("max_scan_time must be greater than zero")
	}
	return duration, nil
}

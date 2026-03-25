package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	App         AppConfig         `yaml:"app"`
	Scan        ScanConfig        `yaml:"scan"`
	Archives    ArchiveConfig     `yaml:"archives"`
	WIM         WIMConfig         `yaml:"wim"`
	SQLite      SQLiteConfig      `yaml:"sqlite"`
	Suppression SuppressionConfig `yaml:"suppression"`
	Rules       RulesConfig       `yaml:"rules"`
	Output      OutputConfig      `yaml:"output"`

	configDir   string `yaml:"-"`
	runtimeRoot string `yaml:"-"`
}

type AppConfig struct {
	Name       string `yaml:"name"`
	LogLevel   string `yaml:"log_level"`
	BannerPath string `yaml:"banner_path"`
}

type ScanConfig struct {
	Targets                    []string `yaml:"targets"`
	TargetsFile                string   `yaml:"targets_file"`
	Profile                    string   `yaml:"profile"`
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
	SeedManifest               string   `yaml:"seed_manifest"`
	ValidationMode             bool     `yaml:"validation_mode"`
	MaxScanTime                string   `yaml:"max_scan_time"`
	CheckpointFile             string   `yaml:"checkpoint_file"`
	Resume                     bool     `yaml:"resume"`
	SkipReachabilityCheck      bool     `yaml:"skip_reachability_check"`
	ReachabilityTimeoutSeconds int      `yaml:"reachability_timeout_seconds"`
}

type ArchiveConfig struct {
	Enabled                  bool  `yaml:"enabled"`
	AutoZIPMaxSize           int64 `yaml:"auto_zip_max_size"`
	AllowLargeZIPs           bool  `yaml:"allow_large_zips"`
	MaxZIPSize               int64 `yaml:"max_zip_size"`
	AutoTARMaxSize           int64 `yaml:"auto_tar_max_size"`
	AllowLargeTARs           bool  `yaml:"allow_large_tars"`
	MaxTARSize               int64 `yaml:"max_tar_size"`
	MaxMembers               int   `yaml:"max_members"`
	MaxMemberBytes           int64 `yaml:"max_member_bytes"`
	MaxTotalUncompressed     int64 `yaml:"max_total_uncompressed_bytes"`
	InspectExtensionlessText bool  `yaml:"inspect_extensionless_text"`
}

type WIMConfig struct {
	Enabled        bool  `yaml:"enabled"`
	AutoWIMMaxSize int64 `yaml:"auto_wim_max_size"`
	AllowLargeWIMs bool  `yaml:"allow_large_wims"`
	MaxWIMSize     int64 `yaml:"max_wim_size"`
	MaxMembers     int   `yaml:"max_members"`
	MaxMemberBytes int64 `yaml:"max_member_bytes"`
	MaxTotalBytes  int64 `yaml:"max_total_bytes"`
}

type SQLiteConfig struct {
	Enabled            bool  `yaml:"enabled"`
	AutoDBMaxSize      int64 `yaml:"auto_db_max_size"`
	AllowLargeDBs      bool  `yaml:"allow_large_dbs"`
	MaxDBSize          int64 `yaml:"max_db_size"`
	MaxTables          int   `yaml:"max_tables"`
	MaxRowsPerTable    int   `yaml:"max_rows_per_table"`
	MaxCellBytes       int64 `yaml:"max_cell_bytes"`
	MaxTotalBytes      int64 `yaml:"max_total_bytes"`
	MaxInterestingCols int   `yaml:"max_interesting_columns"`
}

type SuppressionConfig struct {
	File        string            `yaml:"file"`
	SampleLimit int               `yaml:"sample_limit"`
	Rules       []SuppressionRule `yaml:"rules"`
}

type SuppressionRule struct {
	ID           string   `yaml:"id"`
	Description  string   `yaml:"description"`
	Reason       string   `yaml:"reason"`
	Enabled      bool     `yaml:"enabled"`
	Hosts        []string `yaml:"hosts"`
	Shares       []string `yaml:"shares"`
	RuleIDs      []string `yaml:"rule_ids"`
	Categories   []string `yaml:"categories"`
	ExactPaths   []string `yaml:"exact_paths"`
	PathPrefixes []string `yaml:"path_prefixes"`
	PathContains []string `yaml:"path_contains"`
	Fingerprints []string `yaml:"fingerprints"`
	Tags         []string `yaml:"tags"`
}

type RulesConfig struct {
	Directory     string `yaml:"rules_directory"`
	FailOnInvalid bool   `yaml:"fail_on_invalid"`
}

type OutputConfig struct {
	Format  string `yaml:"output_format"`
	NoTUI   bool   `yaml:"no_tui"`
	JSONOut string `yaml:"json_out"`
	HTMLOut string `yaml:"html_out"`
	CSVOut  string `yaml:"csv_out"`
	MDOut   string `yaml:"md_out"`
	Pretty  bool   `yaml:"pretty"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	resolvedPath := resolveConfigPath(path)
	if strings.TrimSpace(resolvedPath) == "" {
		applyDefaults(&cfg)
		applyPathContext(&cfg, "")
		return cfg, nil
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	var hint struct {
		Scan struct {
			Profile string `yaml:"profile"`
		} `yaml:"scan"`
	}
	if err := yaml.Unmarshal(data, &hint); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if strings.TrimSpace(hint.Scan.Profile) != "" {
		if err := ApplyScanProfile(&cfg, hint.Scan.Profile); err != nil {
			return Config{}, fmt.Errorf("apply scan profile %q: %w", hint.Scan.Profile, err)
		}
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	applyDefaults(&cfg)
	applyPathContext(&cfg, resolvedPath)
	if err := loadSuppressionOverlay(&cfg); err != nil {
		return Config{}, err
	}
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
	if cfg.Archives.AutoZIPMaxSize <= 0 {
		cfg.Archives.AutoZIPMaxSize = 10 * 1024 * 1024
	}
	if cfg.Archives.MaxZIPSize <= 0 {
		cfg.Archives.MaxZIPSize = cfg.Archives.AutoZIPMaxSize
	}
	if cfg.Archives.AutoTARMaxSize <= 0 {
		cfg.Archives.AutoTARMaxSize = 10 * 1024 * 1024
	}
	if cfg.Archives.MaxTARSize <= 0 {
		cfg.Archives.MaxTARSize = cfg.Archives.AutoTARMaxSize
	}
	if cfg.Archives.MaxMembers <= 0 {
		cfg.Archives.MaxMembers = 64
	}
	if cfg.Archives.MaxMemberBytes <= 0 {
		cfg.Archives.MaxMemberBytes = 512 * 1024
	}
	if cfg.Archives.MaxTotalUncompressed <= 0 {
		cfg.Archives.MaxTotalUncompressed = 4 * 1024 * 1024
	}
	if cfg.SQLite.AutoDBMaxSize <= 0 {
		cfg.SQLite.AutoDBMaxSize = 5 * 1024 * 1024
	}
	if cfg.WIM.AutoWIMMaxSize <= 0 {
		cfg.WIM.AutoWIMMaxSize = 128 * 1024 * 1024
	}
	if cfg.WIM.MaxWIMSize <= 0 {
		cfg.WIM.MaxWIMSize = cfg.WIM.AutoWIMMaxSize
	}
	if cfg.WIM.MaxMembers <= 0 {
		cfg.WIM.MaxMembers = 8
	}
	if cfg.WIM.MaxMemberBytes <= 0 {
		cfg.WIM.MaxMemberBytes = 1024 * 1024
	}
	if cfg.WIM.MaxTotalBytes <= 0 {
		cfg.WIM.MaxTotalBytes = 4 * 1024 * 1024
	}
	if cfg.SQLite.MaxDBSize <= 0 {
		cfg.SQLite.MaxDBSize = cfg.SQLite.AutoDBMaxSize
	}
	if cfg.SQLite.MaxTables <= 0 {
		cfg.SQLite.MaxTables = 8
	}
	if cfg.SQLite.MaxRowsPerTable <= 0 {
		cfg.SQLite.MaxRowsPerTable = 5
	}
	if cfg.SQLite.MaxCellBytes <= 0 {
		cfg.SQLite.MaxCellBytes = 256
	}
	if cfg.SQLite.MaxTotalBytes <= 0 {
		cfg.SQLite.MaxTotalBytes = 16 * 1024
	}
	if cfg.SQLite.MaxInterestingCols <= 0 {
		cfg.SQLite.MaxInterestingCols = 4
	}
	if cfg.Suppression.SampleLimit <= 0 {
		cfg.Suppression.SampleLimit = 10
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

func ApplyScanProfile(cfg *Config, profile string) error {
	if cfg == nil {
		return nil
	}
	switch normalizeProfile(profile) {
	case "", "default":
		cfg.Scan.Profile = "default"
		cfg.Scan.ValidationMode = false
		cfg.Archives.Enabled = true
		cfg.Archives.AutoZIPMaxSize = 10 * 1024 * 1024
		cfg.Archives.AllowLargeZIPs = false
		cfg.Archives.MaxZIPSize = 10 * 1024 * 1024
		cfg.Archives.AutoTARMaxSize = 10 * 1024 * 1024
		cfg.Archives.AllowLargeTARs = false
		cfg.Archives.MaxTARSize = 10 * 1024 * 1024
		cfg.Archives.MaxMembers = 64
		cfg.Archives.MaxMemberBytes = 512 * 1024
		cfg.Archives.MaxTotalUncompressed = 4 * 1024 * 1024
		cfg.Archives.InspectExtensionlessText = true
		cfg.WIM.Enabled = true
		cfg.WIM.AutoWIMMaxSize = 128 * 1024 * 1024
		cfg.WIM.AllowLargeWIMs = false
		cfg.WIM.MaxWIMSize = 128 * 1024 * 1024
		cfg.WIM.MaxMembers = 8
		cfg.WIM.MaxMemberBytes = 1024 * 1024
		cfg.WIM.MaxTotalBytes = 4 * 1024 * 1024
		cfg.SQLite.Enabled = true
		cfg.SQLite.AutoDBMaxSize = 5 * 1024 * 1024
		cfg.SQLite.AllowLargeDBs = false
		cfg.SQLite.MaxDBSize = 5 * 1024 * 1024
		cfg.SQLite.MaxTables = 8
		cfg.SQLite.MaxRowsPerTable = 5
		cfg.SQLite.MaxCellBytes = 256
		cfg.SQLite.MaxTotalBytes = 16 * 1024
		cfg.SQLite.MaxInterestingCols = 4
	case "validation":
		cfg.Scan.Profile = "validation"
		cfg.Scan.ValidationMode = true
		cfg.Archives.Enabled = true
		cfg.Archives.AutoZIPMaxSize = 5 * 1024 * 1024
		cfg.Archives.AllowLargeZIPs = false
		cfg.Archives.MaxZIPSize = 5 * 1024 * 1024
		cfg.Archives.AutoTARMaxSize = 5 * 1024 * 1024
		cfg.Archives.AllowLargeTARs = false
		cfg.Archives.MaxTARSize = 5 * 1024 * 1024
		cfg.Archives.MaxMembers = 32
		cfg.Archives.MaxMemberBytes = 256 * 1024
		cfg.Archives.MaxTotalUncompressed = 2 * 1024 * 1024
		cfg.Archives.InspectExtensionlessText = false
		cfg.WIM.Enabled = true
		cfg.WIM.AutoWIMMaxSize = 64 * 1024 * 1024
		cfg.WIM.AllowLargeWIMs = false
		cfg.WIM.MaxWIMSize = 64 * 1024 * 1024
		cfg.WIM.MaxMembers = 6
		cfg.WIM.MaxMemberBytes = 512 * 1024
		cfg.WIM.MaxTotalBytes = 2 * 1024 * 1024
		cfg.SQLite.Enabled = true
		cfg.SQLite.AutoDBMaxSize = 2 * 1024 * 1024
		cfg.SQLite.AllowLargeDBs = false
		cfg.SQLite.MaxDBSize = 2 * 1024 * 1024
		cfg.SQLite.MaxTables = 4
		cfg.SQLite.MaxRowsPerTable = 3
		cfg.SQLite.MaxCellBytes = 192
		cfg.SQLite.MaxTotalBytes = 8 * 1024
		cfg.SQLite.MaxInterestingCols = 3
	case "aggressive":
		cfg.Scan.Profile = "aggressive"
		cfg.Scan.ValidationMode = true
		cfg.Archives.Enabled = true
		cfg.Archives.AutoZIPMaxSize = 10 * 1024 * 1024
		cfg.Archives.AllowLargeZIPs = true
		cfg.Archives.MaxZIPSize = 25 * 1024 * 1024
		cfg.Archives.AutoTARMaxSize = 10 * 1024 * 1024
		cfg.Archives.AllowLargeTARs = false
		cfg.Archives.MaxTARSize = 10 * 1024 * 1024
		cfg.Archives.MaxMembers = 96
		cfg.Archives.MaxMemberBytes = 1024 * 1024
		cfg.Archives.MaxTotalUncompressed = 8 * 1024 * 1024
		cfg.Archives.InspectExtensionlessText = true
		cfg.WIM.Enabled = true
		cfg.WIM.AutoWIMMaxSize = 128 * 1024 * 1024
		cfg.WIM.AllowLargeWIMs = true
		cfg.WIM.MaxWIMSize = 256 * 1024 * 1024
		cfg.WIM.MaxMembers = 12
		cfg.WIM.MaxMemberBytes = 2 * 1024 * 1024
		cfg.WIM.MaxTotalBytes = 8 * 1024 * 1024
		cfg.SQLite.Enabled = true
		cfg.SQLite.AutoDBMaxSize = 5 * 1024 * 1024
		cfg.SQLite.AllowLargeDBs = true
		cfg.SQLite.MaxDBSize = 15 * 1024 * 1024
		cfg.SQLite.MaxTables = 12
		cfg.SQLite.MaxRowsPerTable = 10
		cfg.SQLite.MaxCellBytes = 512
		cfg.SQLite.MaxTotalBytes = 64 * 1024
		cfg.SQLite.MaxInterestingCols = 6
	default:
		return fmt.Errorf("unsupported scan profile %q: use default, validation, or aggressive", profile)
	}
	return nil
}

func normalizeProfile(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func loadSuppressionOverlay(cfg *Config) error {
	if cfg == nil || strings.TrimSpace(cfg.Suppression.File) == "" {
		return nil
	}
	path := resolvePath(cfg.Suppression.File, cfg.configDir, cfg.runtimeRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read suppression file %s: %w", cfg.Suppression.File, err)
	}
	var overlay SuppressionConfig
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return fmt.Errorf("parse suppression file %s: %w", cfg.Suppression.File, err)
	}
	if overlay.SampleLimit > 0 {
		cfg.Suppression.SampleLimit = overlay.SampleLimit
	}
	if len(overlay.Rules) > 0 {
		cfg.Suppression.Rules = append(cfg.Suppression.Rules, overlay.Rules...)
	}
	return nil
}

func (c Config) RulePaths() []string {
	if strings.TrimSpace(c.Rules.Directory) != "" {
		return []string{resolvePath(c.Rules.Directory, c.configDir, c.runtimeRoot)}
	}
	return []string{
		resolvePath(filepath.Join("configs", "rules", "default"), c.runtimeRoot),
		resolvePath(filepath.Join("configs", "rules", "custom"), c.runtimeRoot),
	}
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

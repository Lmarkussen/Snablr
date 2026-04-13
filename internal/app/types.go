package app

type ScanOptions struct {
	ConfigPath                 string
	Targets                    []string
	TargetsFile                string
	Profile                    string
	Username                   string
	Password                   string
	Share                      []string
	ExcludeShare               []string
	Path                       []string
	ExcludePath                []string
	MaxDepth                   int
	Domain                     string
	RulesDirectory             string
	WorkerCount                int
	MaxFileSize                int64
	NoLDAP                     bool
	DomainController           string
	BaseDN                     string
	DiscoverDFS                bool
	PrioritizeADShares         bool
	OnlyADShares               bool
	Baseline                   string
	SeedManifest               string
	ValidationMode             bool
	MaxScanTime                string
	CheckpointFile             string
	Resume                     bool
	SkipReachabilityCheck      bool
	ReachabilityTimeoutSeconds int
	OutputFormat               string
	NoTUI                      bool
	JSONOut                    string
	HTMLOut                    string
	CSVOut                     string
	MDOut                      string
	CredsOut                   string
	ScannedTargetsOut          string
	WIMEnabled                 *bool
	WIMAutoMaxSize             *int64
	WIMAllowLarge              *bool
	WIMMaxSize                 *int64
	WIMMaxMembers              *int
	WIMMaxMemberBytes          *int64
	WIMMaxTotalBytes           *int64
	LogLevel                   string
}

type RulesOptions struct {
	ConfigPath     string
	RulesDirectory string
	LogLevel       string
}

type RulesShowOptions struct {
	RulesOptions
	ID string
}

type RulesTestOptions struct {
	RulesOptions
	RuleFile  string
	InputFile string
	Verbose   bool
}

type RulesTestDirOptions struct {
	RulesOptions
	FixturesDir string
	Verbose     bool
}

type DiffOptions struct {
	OldPath string
	NewPath string
}

type BenchmarkOptions struct {
	ConfigPath     string
	Dataset        string
	RulesDirectory string
	OutPath        string
	LogLevel       string
}

type EvalOptions struct {
	ConfigPath     string
	Dataset        string
	LabelsPath     string
	RulesDirectory string
	OutPath        string
	LogLevel       string
}

type DiscoverOptions struct {
	ConfigPath                 string
	Targets                    []string
	TargetsFile                string
	Username                   string
	Password                   string
	Domain                     string
	NoLDAP                     bool
	DomainController           string
	BaseDN                     string
	DiscoverDFS                bool
	SkipReachabilityCheck      bool
	ReachabilityTimeoutSeconds int
	LogLevel                   string
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

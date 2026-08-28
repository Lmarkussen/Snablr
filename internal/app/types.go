package app

type ScanOptions struct {
	ConfigPath                 string
	Targets                    []string
	TargetsFile                string
	Profile                    string
	AuthMode                   string
	SMBAuth                    string
	Username                   string
	Password                   string
	NTHash                     string
	KerberosCCache             string
	SMBHostname                string
	SMBSPN                     string
	LDAPSPN                    string
	Share                      []string
	ExcludeShare               []string
	Path                       []string
	ExcludePath                []string
	MaxDepth                   int
	Domain                     string
	RulesDirectory             string
	WorkerCount                *int
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
	StateDir                   string
	Incremental                bool
	ForceRescan                bool
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
	ReportBackupArtifacts      bool
	WIMEnabled                 *bool
	WIMAutoMaxSize             *int64
	WIMAllowLarge              *bool
	WIMMaxSize                 *int64
	WIMMaxMembers              *int
	WIMMaxMemberBytes          *int64
	WIMMaxTotalBytes           *int64
	WIMMaxBinaryArtifacts      *int
	WIMMaxBinaryBytes          *int64
	WIMMaxSAMBytes             *int64
	WIMMaxSYSTEMBytes          *int64
	WIMMaxSECURITYBytes        *int64
	WIMMaxNTDSBytes            *int64
	WIMMaxImages               *int
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
	AuthMode                   string
	KerberosCCache             string
	LDAPSPN                    string
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

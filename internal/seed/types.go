package seed

import "time"

type SeedFile struct {
	Category           string
	Format             string
	RelativePath       string
	Filename           string
	Content            []byte
	ExpectedTags       []string
	ExpectedRuleThemes []string
	ExpectedSeverity   string
}

type SeedManifestEntry struct {
	Host               string   `json:"host"`
	Share              string   `json:"share"`
	Path               string   `json:"path"`
	Category           string   `json:"category"`
	Format             string   `json:"format"`
	ExpectedTags       []string `json:"expected_tags,omitempty"`
	ExpectedRuleThemes []string `json:"expected_rule_themes,omitempty"`
	ExpectedSeverity   string   `json:"expected_severity,omitempty"`
	Status             string   `json:"status,omitempty"`
}

type Manifest struct {
	GeneratedAt time.Time           `json:"generated_at"`
	SeedPrefix  string              `json:"seed_prefix"`
	Entries     []SeedManifestEntry `json:"entries"`
}

type GenerateOptions struct {
	CountPerCategory int
	MaxFiles         int
	SeedPrefix       string
	RandomSeed       int64
}

type WriteOptions struct {
	Targets     []string
	Username    string
	Password    string
	Shares      []string
	SeedPrefix  string
	DryRun      bool
	CleanPrefix bool
	ManifestOut string
	RandomSeed  int64
	Logf        func(string, ...any)
	Warnf       func(string, ...any)
	CountPerCat int
	MaxFiles    int
}

type ShareTarget struct {
	Host  string
	Share string
}

type templateSpec struct {
	Category           string
	Formats            []string
	Directories        []string
	FilenamePrefixes   []string
	ExpectedTags       []string
	ExpectedRuleThemes []string
	ExpectedSeverity   string
	Render             func(renderContext) []byte
}

type renderContext struct {
	Index    int
	Format   string
	Filename string
	Token    string
}

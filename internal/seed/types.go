package seed

import "time"

type SeedFile struct {
	Category            string
	Format              string
	RelativePath        string
	Filename            string
	ExpectedPath        string
	Content             []byte
	IntendedAs          string
	ExpectedClass       string
	ExpectedTriageClass string
	ExpectedConfidence  string
	ExpectedCorrelated  bool
	ExpectedSignalTypes []string
	ExpectedTags        []string
	ExpectedRuleThemes  []string
	ExpectedSeverity    string
}

type SeedManifestEntry struct {
	Host                string   `json:"host"`
	Share               string   `json:"share"`
	Path                string   `json:"path"`
	Category            string   `json:"category"`
	Format              string   `json:"format"`
	IntendedAs          string   `json:"intended_as,omitempty"`
	ExpectedClass       string   `json:"expected_class,omitempty"`
	ExpectedTriageClass string   `json:"expected_triage_class,omitempty"`
	ExpectedConfidence  string   `json:"expected_confidence,omitempty"`
	ExpectedCorrelated  bool     `json:"expected_correlated,omitempty"`
	ExpectedSignalTypes []string `json:"expected_signal_types,omitempty"`
	ExpectedTags        []string `json:"expected_tags,omitempty"`
	ExpectedRuleThemes  []string `json:"expected_rule_themes,omitempty"`
	ExpectedSeverity    string   `json:"expected_severity,omitempty"`
	Status              string   `json:"status,omitempty"`
}

type Manifest struct {
	GeneratedAt time.Time           `json:"generated_at"`
	SeedPrefix  string              `json:"seed_prefix"`
	Entries     []SeedManifestEntry `json:"entries"`
}

type GenerateOptions struct {
	CountPerCategory    int
	MaxFiles            int
	Depth               int
	SeedPrefix          string
	RandomSeed          int64
	LikelyHitRatio      int
	FilenameOnlyRatio   int
	HighSeverityRatio   int
	MediumSeverityRatio int
}

type WriteOptions struct {
	Targets             []string
	Username            string
	Password            string
	Shares              []string
	IncludeAdminShares  bool
	SeedPrefix          string
	DryRun              bool
	CleanPrefix         bool
	ManifestOut         string
	RandomSeed          int64
	Depth               int
	SharesPerTarget     int
	LikelyHitRatio      int
	FilenameOnlyRatio   int
	HighSeverityRatio   int
	MediumSeverityRatio int
	Logf                func(string, ...any)
	Warnf               func(string, ...any)
	CountPerCat         int
	MaxFiles            int
}

type ShareTarget struct {
	Host  string
	Share string
}

type templateSpec struct {
	Category        string
	Directories     []string
	Variants        []templateVariant
	Personas        []string
	ServiceAccounts []string
	Labels          []string
	Render          func(renderContext, templateVariant) []byte
}

type templateVariant struct {
	Filename            string
	Format              string
	ExpectedInnerPath   string
	IntendedAs          string
	ExpectedClass       string
	ExpectedTriageClass string
	ExpectedConfidence  string
	ExpectedCorrelated  bool
	ExpectedSignalTypes []string
	ExpectedTags        []string
	ExpectedRuleThemes  []string
	ExpectedSeverity    string
	ContentStyle        string
}

type renderContext struct {
	Index          int
	Format         string
	Filename       string
	Token          string
	Category       string
	Directory      string
	Persona        string
	PersonaDisplay string
	ServiceAccount string
	Label          string
	IntendedAs     string
	ContentStyle   string
}

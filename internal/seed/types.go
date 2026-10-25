package seed

import "time"

type SeedFile struct {
	Category                     string
	Format                       string
	RelativePath                 string
	Filename                     string
	ExpectedPath                 string
	Content                      []byte
	IntendedAs                   string
	ExpectedClass                string
	ExpectedTriageClass          string
	ExpectedConfidence           string
	ExpectedCorrelated           bool
	ExpectedSignalTypes          []string
	ExpectedTags                 []string
	ExpectedRuleThemes           []string
	ExpectedSeverity             string
	ExpectedUsername             string
	ExpectedPassword             string
	ExpectedPairing              string
	ExpectedOrigin               string
	ExpectedPairs                int
	ExpectedObservations         int
	ExpectedInspectable          bool
	ExpectedArchive              bool
	FixtureID                    string
	Subset                       string
	SeedVariant                  string
	ExpectedPairsDetail          []ExpectedCredentialPair `json:"-"`
	NegativeReason               string
	ExpectedOwner                string
	ExpectedFinderCategory       string
	ExpectedProvenance           string
	ExpectedGrouping             string
	ExpectedCorrelationSemantics string
	SupportStatus                string
	ExpectedJustification        string
}

// ExpectedCredentialPair is synthetic ground truth for the credential audit
// corpus. It is deliberately kept on the manifest side of the seeder and is
// never consumed by the scanner or Finder.
type ExpectedCredentialPair struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Pairing       string `json:"pairing"`
	Origin        string `json:"origin,omitempty"`
	SourceContext string `json:"source_context,omitempty"`
}

type SeedManifestEntry struct {
	Host                         string                   `json:"host"`
	Share                        string                   `json:"share"`
	Path                         string                   `json:"path"`
	Category                     string                   `json:"category"`
	Format                       string                   `json:"format"`
	IntendedAs                   string                   `json:"intended_as,omitempty"`
	ExpectedClass                string                   `json:"expected_class,omitempty"`
	ExpectedTriageClass          string                   `json:"expected_triage_class,omitempty"`
	ExpectedConfidence           string                   `json:"expected_confidence,omitempty"`
	ExpectedCorrelated           bool                     `json:"expected_correlated,omitempty"`
	ExpectedSignalTypes          []string                 `json:"expected_signal_types,omitempty"`
	ExpectedTags                 []string                 `json:"expected_tags,omitempty"`
	ExpectedRuleThemes           []string                 `json:"expected_rule_themes,omitempty"`
	ExpectedSeverity             string                   `json:"expected_severity,omitempty"`
	ExpectedUsername             string                   `json:"expected_username,omitempty"`
	ExpectedPassword             string                   `json:"expected_password,omitempty"`
	ExpectedPairing              string                   `json:"expected_pairing,omitempty"`
	ExpectedOrigin               string                   `json:"expected_origin,omitempty"`
	ExpectedPairs                int                      `json:"expected_pairs"`
	ExpectedObservations         int                      `json:"expected_observations"`
	ExpectedInspectable          bool                     `json:"expected_inspectable,omitempty"`
	ExpectedArchive              bool                     `json:"expected_archive_provenance,omitempty"`
	Status                       string                   `json:"status,omitempty"`
	FixtureID                    string                   `json:"fixture_id,omitempty"`
	Subset                       string                   `json:"subset,omitempty"`
	SeedVariant                  string                   `json:"seed_variant,omitempty"`
	ExpectedPairsDetail          []ExpectedCredentialPair `json:"expected_pairs_detail,omitempty"`
	NegativeReason               string                   `json:"negative_reason,omitempty"`
	ExpectedOwner                string                   `json:"expected_owner,omitempty"`
	ExpectedFinderCategory       string                   `json:"expected_finder_category,omitempty"`
	ExpectedProvenance           string                   `json:"expected_provenance,omitempty"`
	ExpectedGrouping             string                   `json:"expected_grouping,omitempty"`
	ExpectedCorrelationSemantics string                   `json:"expected_correlation_semantics,omitempty"`
	SupportStatus                string                   `json:"support_status,omitempty"`
	ExpectedJustification        string                   `json:"expected_justification,omitempty"`
}

type Manifest struct {
	GeneratedAt    time.Time           `json:"generated_at"`
	FixtureVersion string              `json:"fixture_version,omitempty"`
	SeedPrefix     string              `json:"seed_prefix"`
	FileCount      int                 `json:"file_count,omitempty"`
	DirectoryCount int                 `json:"directory_count,omitempty"`
	Families       map[string]int      `json:"families,omitempty"`
	Entries        []SeedManifestEntry `json:"entries"`
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
	Expanded            bool
	Credentials         bool
	CredentialsV2       bool
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
	Expanded            bool
	Credentials         bool
	CredentialsV2       bool
	RequireGroundTruth  bool
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

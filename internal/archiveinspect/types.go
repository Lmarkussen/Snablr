package archiveinspect

type Options struct {
	Enabled                  bool
	AutoZIPMaxSize           int64
	AllowLargeZIPs           bool
	MaxZIPSize               int64
	MaxMembers               int
	MaxMemberBytes           int64
	MaxTotalUncompressed     int64
	InspectExtensionlessText bool
}

type Candidate struct {
	Name      string
	Extension string
	Size      int64
}

type Member struct {
	Path      string
	Name      string
	Extension string
	Size      int64
	Content   []byte
}

type Result struct {
	Inspected        bool
	InspectedLocally bool
	SkipReason       string
	Members          []Member
}

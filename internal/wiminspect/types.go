package wiminspect

type Options struct {
	Enabled           bool
	AutoWIMMaxSize    int64
	AllowLargeWIMs    bool
	MaxWIMSize        int64
	MaxMembers        int
	MaxMemberBytes    int64
	MaxTotalBytes     int64
}

type Candidate struct {
	Name      string
	Extension string
	Size      int64
}

type Member struct {
	Path        string
	Name        string
	Extension   string
	Size        int64
	Content     []byte
	ContentRead bool
}

type Result struct {
	Inspected        bool
	InspectedLocally bool
	SkipReason       string
	Members          []Member
}

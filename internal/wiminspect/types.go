package wiminspect

import "snablr/internal/artifact"

type Options struct {
	Enabled            bool
	AutoWIMMaxSize     int64
	AllowLargeWIMs     bool
	MaxWIMSize         int64
	MaxMembers         int
	MaxMemberBytes     int64
	MaxTotalBytes      int64
	MaxBinaryArtifacts int
	MaxBinaryBytes     int64
	MaxSAMBytes        int64
	MaxSYSTEMBytes     int64
	MaxSECURITYBytes   int64
	MaxNTDSBytes       int64
	MaxImages          int
	// OfficeInterest reports whether an Office document member is an
	// interesting content candidate. It lets the caller reuse the configured
	// filename/path discovery rules instead of duplicating vocabulary here.
	// Targeting stays bounded by MaxMembers, MaxMemberBytes, and MaxTotalBytes.
	OfficeInterest func(memberPath string) bool
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
	ImageIndex  int
}

type BinaryMember struct {
	Path       string
	Name       string
	Extension  string
	Size       int64
	Artifact   artifact.Binary
	ImageIndex int
}

type Result struct {
	Inspected        bool
	InspectedLocally bool
	SkipReason       string
	Members          []Member
	BinaryMembers    []BinaryMember
	Cleanup          func() error
}

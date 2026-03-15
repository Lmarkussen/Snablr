package planner

type PlannedTarget struct {
	Host     string
	Share    string
	Path     string
	Priority int
	Reason   string
	Source   string
}

type FilterOptions struct {
	IncludeShares []string
	ExcludeShares []string
	IncludePaths  []string
	ExcludePaths  []string
	MaxDepth      int
}

type HostInput struct {
	Host   string
	Source string
}

type ShareInput struct {
	Host               string
	Share              string
	Source             string
	PrioritizeADShares bool
}

type FileInput struct {
	Host               string
	Share              string
	Path               string
	Extension          string
	Source             string
	PrioritizeADShares bool
}

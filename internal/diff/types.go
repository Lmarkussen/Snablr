package diff

import "snablr/internal/scanner"

type FindingFingerprint struct {
	RuleID   string `json:"rule_id"`
	Host     string `json:"host"`
	Share    string `json:"share"`
	FilePath string `json:"file_path"`
	Match    string `json:"match"`
}

type Status string

const (
	StatusNew       Status = "new"
	StatusRemoved   Status = "removed"
	StatusChanged   Status = "changed"
	StatusUnchanged Status = "unchanged"
)

type ChangedFinding struct {
	Previous      scanner.Finding    `json:"previous"`
	Current       scanner.Finding    `json:"current"`
	Fingerprint   FindingFingerprint `json:"fingerprint"`
	ChangedFields []string           `json:"changed_fields,omitempty"`
}

type DiffResult struct {
	New       []scanner.Finding `json:"new,omitempty"`
	Removed   []scanner.Finding `json:"removed,omitempty"`
	Changed   []ChangedFinding  `json:"changed,omitempty"`
	Unchanged []scanner.Finding `json:"unchanged,omitempty"`
}

type Summary struct {
	New       int `json:"new"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

type FindingDelta struct {
	Status        Status             `json:"status"`
	Fingerprint   FindingFingerprint `json:"fingerprint"`
	ChangedFields []string           `json:"changed_fields,omitempty"`
}

type Report struct {
	Findings []scanner.Finding `json:"findings"`
}

func (r DiffResult) Summary() Summary {
	return Summary{
		New:       len(r.New),
		Removed:   len(r.Removed),
		Changed:   len(r.Changed),
		Unchanged: len(r.Unchanged),
	}
}

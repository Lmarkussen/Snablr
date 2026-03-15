package state

import "time"

type Checkpoint struct {
	Version         int       `json:"version"`
	UpdatedAt       time.Time `json:"updated_at"`
	CompletedHosts  []string  `json:"completed_hosts,omitempty"`
	CompletedShares []string  `json:"completed_shares,omitempty"`
	CompletedFiles  []string  `json:"completed_files,omitempty"`
}

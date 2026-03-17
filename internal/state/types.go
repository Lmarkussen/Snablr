package state

import "time"

type CompletedFileState struct {
	Key        string    `json:"key"`
	Size       int64     `json:"size,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
}

type Checkpoint struct {
	Version         int                  `json:"version"`
	UpdatedAt       time.Time            `json:"updated_at"`
	CompletedHosts  []string             `json:"completed_hosts,omitempty"`
	CompletedShares []string             `json:"completed_shares,omitempty"`
	CompletedFiles  []string             `json:"completed_files,omitempty"`
	FileStates      []CompletedFileState `json:"file_states,omitempty"`
}

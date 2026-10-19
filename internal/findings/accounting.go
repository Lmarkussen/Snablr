package findings

import (
	"fmt"
	"sort"
	"strings"
)

// ProjectionAudit describes how every persisted credential row is represented
// by the Finder read model. It intentionally contains stable row references,
// not credential values, so it is safe for diagnostics and regression output.
type ProjectionAudit struct {
	ScanID                   string         `json:"scan_id"`
	TotalPersistedRows       int            `json:"total_persisted_rows"`
	PresentedRows            int            `json:"presented_rows"`
	GroupedRows              int            `json:"grouped_rows"`
	ExcludedRows             int            `json:"excluded_rows"`
	UnaccountedRows          int            `json:"unaccounted_rows"`
	LogicalDiscoveryCount    int            `json:"logical_discovery_count"`
	SourceObservationCount   int            `json:"source_observation_count"`
	ExcludedByReason         map[string]int `json:"excluded_by_reason,omitempty"`
	UnaccountedRefs          []string       `json:"unaccounted_refs,omitempty"`
	MissingCredentialKeyRefs []string       `json:"missing_credential_key_refs,omitempty"`
}

// credentialRowRef is the stable link between a provider row and a Finder
// discovery. CredentialKey is unique within a scan; the row-ID fallback keeps
// malformed historical rows traceable without inventing a content key.
func credentialRowRef(item Credential) string {
	if key := strings.TrimSpace(item.CredentialKey); key != "" {
		return key
	}
	return fmt.Sprintf("row:%d", item.ID)
}

func auditCredentialProjection(scanID string, credentials []Credential, categories []category) ProjectionAudit {
	audit := ProjectionAudit{
		ScanID:             scanID,
		TotalPersistedRows: len(credentials),
		ExcludedByReason:   make(map[string]int),
	}
	accounted := make(map[string]struct{}, len(credentials))
	presented := make(map[string]struct{}, len(credentials))
	grouped := make(map[string]struct{}, len(credentials))
	seenSources := make(map[string]struct{}, len(credentials))
	for _, item := range credentials {
		ref := credentialRowRef(item)
		if strings.TrimSpace(item.CredentialKey) == "" {
			audit.MissingCredentialKeyRefs = append(audit.MissingCredentialKeyRefs, ref)
		}
		if source := credentialSourceObservation(item); source != "" {
			seenSources[source] = struct{}{}
		} else {
			seenSources["row:"+ref] = struct{}{}
		}
	}
	for _, group := range categories {
		for _, discovery := range group.Discoveries {
			if len(discovery.PersistedRefs) == 0 {
				continue
			}
			audit.LogicalDiscoveryCount++
			for index, ref := range discovery.PersistedRefs {
				if index == 0 {
					presented[ref] = struct{}{}
				} else {
					grouped[ref] = struct{}{}
				}
				accounted[ref] = struct{}{}
			}
		}
	}
	audit.PresentedRows = len(presented)
	audit.GroupedRows = len(grouped)
	audit.SourceObservationCount = len(seenSources)
	for _, item := range credentials {
		ref := credentialRowRef(item)
		if _, ok := accounted[ref]; !ok {
			audit.UnaccountedRefs = append(audit.UnaccountedRefs, ref)
		}
	}
	// Exclusions are intentionally empty in this first accounting milestone:
	// invalid, opaque, password-only, and review rows remain visible in Finder
	// review categories rather than being hidden.
	audit.UnaccountedRows = len(audit.UnaccountedRefs)
	if audit.PresentedRows+audit.GroupedRows+audit.ExcludedRows+audit.UnaccountedRows != audit.TotalPersistedRows {
		// Keep the diagnostic internally consistent even if a future projection
		// adds exclusions without updating the accounting traversal.
		audit.UnaccountedRows = audit.TotalPersistedRows - audit.PresentedRows - audit.GroupedRows - audit.ExcludedRows
	}
	sort.Strings(audit.UnaccountedRefs)
	sort.Strings(audit.MissingCredentialKeyRefs)
	return audit
}

func credentialSourceObservation(item Credential) string {
	candidate := item.Candidate
	parts := []string{candidate.Host, candidate.Share, candidate.Path, candidate.Container}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if strings.Join(parts, "") == "" {
		return ""
	}
	return strings.Join(parts, "\x00")
}

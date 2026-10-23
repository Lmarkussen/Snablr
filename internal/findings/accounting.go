package findings

import (
	"fmt"
	"sort"
	"strings"
)

// ProjectionAudit describes how every persisted material row is represented by
// the Finder read model. It intentionally contains stable row references, not
// evidence values, so it is safe for diagnostics and regression output.
type ProjectionAudit struct {
	ScanID                   string         `json:"scan_id"`
	TotalPersistedRows       int            `json:"total_persisted_rows"`
	PresentedRows            int            `json:"presented_rows"`
	GroupedRows              int            `json:"grouped_rows"`
	ExcludedRows             int            `json:"excluded_rows"`
	UnaccountedRows          int            `json:"unaccounted_rows"`
	LogicalDiscoveryCount    int            `json:"logical_discovery_count"`
	SourceObservationCount   int            `json:"source_observation_count"`
	PersistedFindingRows     int            `json:"persisted_finding_rows"`
	PersistedCorrelationRows int            `json:"persisted_correlation_rows"`
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

func findingRowRef(item Finding) string { return fmt.Sprintf("finding:%d", item.ID) }

func correlationRowRef(item Correlation) string { return "correlation:" + item.Key }

func auditProjection(scanID string, credentials []Credential, findings []Finding, correlations []Correlation, categories []category) ProjectionAudit {
	audit := ProjectionAudit{
		ScanID:                   scanID,
		TotalPersistedRows:       len(credentials) + len(findings) + len(correlations),
		PersistedFindingRows:     len(findings),
		PersistedCorrelationRows: len(correlations),
		ExcludedByReason:         make(map[string]int),
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
	for _, item := range findings {
		seenSources["finding:"+item.Finding.Host+"\x00"+item.Finding.Share+"\x00"+item.Finding.FilePath] = struct{}{}
	}
	for _, item := range correlations {
		seenSources[correlationRowRef(item)] = struct{}{}
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
	refs := make([]string, 0, audit.TotalPersistedRows)
	for _, item := range credentials {
		refs = append(refs, credentialRowRef(item))
	}
	for _, item := range findings {
		refs = append(refs, findingRowRef(item))
	}
	for _, item := range correlations {
		refs = append(refs, correlationRowRef(item))
	}
	for _, ref := range refs {
		if _, ok := accounted[ref]; !ok {
			audit.UnaccountedRefs = append(audit.UnaccountedRefs, ref)
		}
	}
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

func auditCredentialProjection(scanID string, credentials []Credential, categories []category) ProjectionAudit {
	return auditProjection(scanID, credentials, nil, nil, categories)
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

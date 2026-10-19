package credentialanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Correlation is a bounded, non-secret relationship between independently
// observed credential records. It never carries the credential value itself.
type Correlation struct {
	Key                 string              `json:"-"`
	Type                string              `json:"type"`
	Identity            string              `json:"identity"`
	Domain              string              `json:"domain,omitempty"`
	CredentialType      string              `json:"credential_type"`
	Sources             []CorrelationSource `json:"sources"`
	ObservationCount    int                 `json:"observation_count"`
	Confidence          string              `json:"confidence"`
	ConfidenceRationale string              `json:"confidence_rationale"`
}

type CorrelationSource struct {
	Host      string     `json:"host,omitempty"`
	Share     string     `json:"share,omitempty"`
	Path      string     `json:"path"`
	Container string     `json:"container,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
}

// Correlate builds deterministic, scan-scoped relationships from candidates.
// Only candidates with explicit non-placeholder identities, a credential type,
// and distinct source origins participate. Values are compared internally but
// are never copied into the correlation payload.
func Correlate(candidates []Candidate) []Correlation {
	groups := make(map[string][]Candidate)
	for _, candidate := range candidates {
		if _, suppressed := SuppressionReason(candidate); suppressed {
			continue
		}
		identity := strings.TrimSpace(candidate.Identity)
		credentialType := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
		if identity == "" || IsPlaceholderIdentity(identity) || credentialType == "" || strings.TrimSpace(candidate.Path) == "" {
			continue
		}
		key := strings.Join([]string{strings.ToLower(strings.TrimSpace(candidate.Domain)), strings.ToLower(identity), credentialType}, "\x00")
		groups[key] = append(groups[key], candidate)
	}

	correlations := make([]Correlation, 0)
	for groupKey, group := range groups {
		byOrigin := make(map[string]Candidate)
		for _, candidate := range group {
			origin := candidateOrigin(candidate)
			if origin == "" {
				continue
			}
			if existing, ok := byOrigin[origin]; !ok || preferCorrelationCandidate(candidate, existing) {
				byOrigin[origin] = candidate
			}
		}
		if len(byOrigin) < 2 {
			continue
		}
		origins := make([]string, 0, len(byOrigin))
		for origin := range byOrigin {
			origins = append(origins, origin)
		}
		sort.Strings(origins)
		sources := make([]CorrelationSource, 0, len(origins))
		for _, origin := range origins {
			candidate := byOrigin[origin]
			sources = append(sources, CorrelationSource{Host: candidate.Host, Share: candidate.Share, Path: candidate.Path, Container: candidate.Container, Evidence: append([]Evidence(nil), candidate.Evidence...)})
		}
		first := byOrigin[origins[0]]
		sameValue := true
		for _, origin := range origins[1:] {
			if byOrigin[origin].Value != first.Value {
				sameValue = false
				break
			}
		}
		confidence, rationale := "medium", "the same normalized identity and credential type were observed in distinct source files"
		correlationType := "same_identity_type"
		if sameValue {
			confidence = "high"
			correlationType = "same_identity_value"
			rationale = "the same normalized identity, credential type, and credential material were observed in distinct source files"
		}
		correlation := Correlation{Type: correlationType, Identity: first.Identity, Domain: first.Domain, CredentialType: first.CredentialType, Sources: sources, ObservationCount: len(origins), Confidence: confidence, ConfidenceRationale: rationale}
		correlation.Key = correlationKey(groupKey, origins)
		correlations = append(correlations, correlation)
	}

	sort.Slice(correlations, func(i, j int) bool { return correlations[i].Key < correlations[j].Key })
	return correlations
}

func candidateOrigin(candidate Candidate) string {
	host := strings.ToLower(strings.TrimSpace(candidate.Host))
	share := strings.ToLower(strings.TrimSpace(candidate.Share))
	path := strings.TrimSpace(candidate.Path)
	container := strings.TrimSpace(candidate.Container)
	if container != "" {
		qualifiedPrefix := container + "!"
		if strings.HasPrefix(path, qualifiedPrefix) {
			path = strings.TrimPrefix(path, qualifiedPrefix)
		}
		path = container + "!" + path
	}
	return strings.Join([]string{host, share, path}, "\x00")
}

func preferCorrelationCandidate(candidate, existing Candidate) bool {
	if candidate.Verification == Confirmed && existing.Verification != Confirmed {
		return true
	}
	return len(candidate.Evidence) > len(existing.Evidence)
}

func correlationKey(group string, origins []string) string {
	value := group + "\x00" + strings.Join(origins, "\x00")
	digest := sha256.Sum256([]byte(value))
	return "credential:" + hex.EncodeToString(digest[:])
}

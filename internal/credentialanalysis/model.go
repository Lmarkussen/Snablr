// Package credentialanalysis classifies extracted credential-like material
// after scanning. Sensitive values live only in memory and are intentionally
// omitted from the exported report model.
package credentialanalysis

import (
	"sort"
	"strings"
)

type Verification string

const (
	Confirmed Verification = "confirmed"
	Review    Verification = "review"
)

type Candidate struct {
	Verification    Verification
	CredentialType  string
	Identity        string
	Domain          string
	Value           string `json:"-"`
	RID             uint32
	SID             string
	AccountType     string
	Disabled        bool
	Encrypted       bool
	Source          string
	Host            string
	Share           string
	Path            string
	Container       string
	ValidationBasis string
	ReviewReasons   []string
	Evidence        []Evidence
}

type Evidence struct {
	RuleID   string `json:"rule_id,omitempty"`
	Source   string `json:"source,omitempty"`
	Path     string `json:"path,omitempty"`
	Location string `json:"location,omitempty"`
}

// SafeCandidate is the report/export-independent projection. Value is never
// included; explicit sensitive exporters may use the in-memory Candidate.
type SafeCandidate struct {
	Verification    Verification `json:"verification"`
	CredentialType  string       `json:"credential_type"`
	Identity        string       `json:"identity,omitempty"`
	Domain          string       `json:"domain,omitempty"`
	ValuePresent    bool         `json:"value_present"`
	RID             uint32       `json:"rid,omitempty"`
	SID             string       `json:"sid,omitempty"`
	AccountType     string       `json:"account_type,omitempty"`
	Disabled        bool         `json:"disabled,omitempty"`
	Encrypted       bool         `json:"encrypted,omitempty"`
	Source          string       `json:"source,omitempty"`
	Host            string       `json:"host,omitempty"`
	Share           string       `json:"share,omitempty"`
	Path            string       `json:"path,omitempty"`
	Container       string       `json:"container,omitempty"`
	ValidationBasis string       `json:"validation_basis,omitempty"`
	ReviewReasons   []string     `json:"review_reasons,omitempty"`
	Evidence        []Evidence   `json:"evidence,omitempty"`
}

type Report struct {
	CandidatesAnalyzed int             `json:"candidates_analyzed"`
	Confirmed          []SafeCandidate `json:"confirmed,omitempty"`
	Review             []SafeCandidate `json:"review,omitempty"`
	DuplicatesMerged   int             `json:"duplicates_merged"`
	Candidates         []Candidate     `json:"-"`
}

type analyzedCandidate struct {
	Candidate
	key string
}

func Analyze(candidates []Candidate) Report {
	report := Report{}
	merged := make(map[string]analyzedCandidate)
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Value) == "" || strings.TrimSpace(candidate.CredentialType) == "" {
			continue
		}
		report.CandidatesAnalyzed++
		candidate = normalize(candidate)
		// Verification is deliberately not part of identity: independent evidence
		// may promote an initially reviewed candidate to confirmed.
		key := candidateKey(candidate)
		if equivalentKey, ok := findUnassociatedEquivalent(merged, candidate); ok {
			if candidate.Identity == "" {
				key = equivalentKey
			} else {
				// A stronger structured record supersedes an earlier unassociated
				// bridge candidate while retaining its evidence.
				existing := merged[equivalentKey]
				delete(merged, equivalentKey)
				if existing.Identity == "" {
					existing.Identity = candidate.Identity
				}
				merged[key] = existing
			}
		}
		if existing, ok := merged[key]; ok {
			if existing.Verification != Confirmed && candidate.Verification == Confirmed {
				existing.Verification = Confirmed
				existing.ValidationBasis = candidate.ValidationBasis
				existing.ReviewReasons = nil
			}
			existing.Candidate.Evidence = mergeEvidence(existing.Candidate.Evidence, candidate.Evidence)
			if existing.Verification != Confirmed {
				existing.Candidate.ReviewReasons = mergeStrings(existing.Candidate.ReviewReasons, candidate.ReviewReasons)
			} else {
				existing.Candidate.ReviewReasons = nil
			}
			if existing.Candidate.Source == "" {
				existing.Candidate.Source = candidate.Source
			}
			merged[key] = existing
			report.DuplicatesMerged++
			continue
		}
		merged[key] = analyzedCandidate{Candidate: candidate, key: key}
	}
	all := make([]analyzedCandidate, 0, len(merged))
	for _, candidate := range merged {
		all = append(all, candidate)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key < all[j].key })
	for _, candidate := range all {
		report.Candidates = append(report.Candidates, candidate.Candidate)
		safe := toSafe(candidate.Candidate)
		if candidate.Verification == Confirmed {
			report.Confirmed = append(report.Confirmed, safe)
		} else {
			report.Review = append(report.Review, safe)
		}
	}
	return report
}

func candidateKey(candidate Candidate) string {
	return strings.ToLower(candidate.CredentialType) + "\x00" + strings.ToLower(candidate.Domain) + "\x00" + strings.ToLower(candidate.Identity) + "\x00" + candidate.Value
}

func findUnassociatedEquivalent(merged map[string]analyzedCandidate, candidate Candidate) (string, bool) {
	for key, existing := range merged {
		if !strings.EqualFold(existing.CredentialType, candidate.CredentialType) ||
			!strings.EqualFold(existing.Domain, candidate.Domain) || existing.Value != candidate.Value {
			continue
		}
		if candidate.Identity == "" && existing.Identity != "" {
			return key, true
		}
		if candidate.Identity != "" && existing.Identity == "" {
			return key, true
		}
	}
	return "", false
}

func normalize(candidate Candidate) Candidate {
	candidate.Verification = Verification(strings.ToLower(strings.TrimSpace(string(candidate.Verification))))
	if candidate.Verification != Confirmed {
		candidate.Verification = Review
	}
	candidate.CredentialType = strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	candidate.Identity = strings.TrimSpace(candidate.Identity)
	candidate.Domain = strings.TrimSpace(candidate.Domain)
	candidate.Source = strings.TrimSpace(candidate.Source)
	candidate.Path = strings.TrimSpace(candidate.Path)
	candidate.ValidationBasis = strings.TrimSpace(candidate.ValidationBasis)
	candidate.ReviewReasons = uniqueSorted(candidate.ReviewReasons)
	candidate.Evidence = mergeEvidence(nil, candidate.Evidence)
	return candidate
}

func toSafe(candidate Candidate) SafeCandidate {
	return SafeCandidate{
		Verification: candidate.Verification, CredentialType: candidate.CredentialType,
		Identity: candidate.Identity, Domain: candidate.Domain, ValuePresent: candidate.Value != "",
		RID: candidate.RID, SID: candidate.SID, AccountType: candidate.AccountType, Disabled: candidate.Disabled, Encrypted: candidate.Encrypted,
		Source: candidate.Source, Host: candidate.Host, Share: candidate.Share, Path: candidate.Path,
		Container: candidate.Container, ValidationBasis: candidate.ValidationBasis,
		ReviewReasons: append([]string{}, candidate.ReviewReasons...), Evidence: append([]Evidence{}, candidate.Evidence...),
	}
}

func mergeEvidence(left, right []Evidence) []Evidence {
	seen := make(map[Evidence]struct{}, len(left)+len(right))
	out := make([]Evidence, 0, len(left)+len(right))
	for _, evidence := range append(append([]Evidence{}, left...), right...) {
		if _, ok := seen[evidence]; ok {
			continue
		}
		seen[evidence] = struct{}{}
		out = append(out, evidence)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func mergeStrings(left, right []string) []string {
	return uniqueSorted(append(append([]string{}, left...), right...))
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

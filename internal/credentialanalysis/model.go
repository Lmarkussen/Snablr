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
		// may promote an initially reviewed candidate to confirmed. A weaker
		// Review record for the same logical credential is folded into the
		// Confirmed record (evidence retained) instead of being reported twice.
		mergedCandidate := false
		for {
			if equivalentKey, ok := findLogicalEquivalent(merged, candidate); ok {
				existing := merged[equivalentKey]
				delete(merged, equivalentKey)
				candidate = mergeLogicalCredential(existing.Candidate, candidate)
				mergedCandidate = true
				continue
			}
			key := recordKey(candidate)
			existing, ok := merged[key]
			if !ok {
				merged[key] = analyzedCandidate{Candidate: candidate, key: key}
				break
			}
			// Defensive: identical logical key and origin must merge too.
			delete(merged, key)
			candidate = mergeLogicalCredential(existing.Candidate, candidate)
			mergedCandidate = true
		}
		if mergedCandidate {
			report.DuplicatesMerged++
		}
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

// recordKey identifies one stored logical record: the credential key plus the
// logical origin, so identical credentials found in unrelated files stay
// separate while every piece of evidence for one origin merges into one record.
func recordKey(candidate Candidate) string {
	return candidateKey(candidate) + "\x00" + logicalOrigin(candidate.Path)
}

// findLogicalEquivalent returns the key of an already-merged record describing
// the same logical credential. Candidate order is not significant: the lowest
// matching key is chosen so merging is deterministic.
func findLogicalEquivalent(merged map[string]analyzedCandidate, candidate Candidate) (string, bool) {
	var matches []string
	for key, existing := range merged {
		if sameLogicalCredential(existing.Candidate, candidate) {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return "", false
	}
	sort.Strings(matches)
	return matches[0], true
}

// sameLogicalCredential reports whether two candidates describe one logical
// credential: same normalized type, same value, compatible identity and domain,
// and a compatible logical origin.
//
// Identity and domain are compatible when they are equal, or when one side does
// not know them yet. Two different non-empty identities (or domains) are
// deliberately kept apart so that distinct accounts sharing a password are
// never collapsed.
func sameLogicalCredential(left, right Candidate) bool {
	if !strings.EqualFold(strings.TrimSpace(left.CredentialType), strings.TrimSpace(right.CredentialType)) {
		return false
	}
	if left.Value != right.Value {
		return false
	}
	if !compatibleField(left.Identity, right.Identity) || !compatibleField(left.Domain, right.Domain) {
		return false
	}
	return originsCompatible(left, right)
}

func compatibleField(left, right string) bool {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == "" || right == "" {
		return true
	}
	return strings.EqualFold(left, right)
}

// originsCompatible keeps unrelated material apart while still merging the two
// paths that describe the same document (a generic finding record and a
// structured harvester record for one Office member, for example).
//
// Origins are compatible when either side is unknown, when both resolve to the
// same logical container/document, or when both records already agree on a
// non-empty identity (the same account observed in more than one location).
func originsCompatible(left, right Candidate) bool {
	leftPath, rightPath := strings.TrimSpace(left.Path), strings.TrimSpace(right.Path)
	if leftPath == "" || rightPath == "" {
		return true
	}
	if logicalOrigin(leftPath) == logicalOrigin(rightPath) {
		return true
	}
	if leftIdentity := strings.TrimSpace(left.Identity); leftIdentity != "" && strings.EqualFold(leftIdentity, strings.TrimSpace(right.Identity)) {
		return true
	}
	leftSource, rightSource := strings.TrimSpace(left.Source), strings.TrimSpace(right.Source)
	if leftSource != "" && logicalOrigin(leftSource) == logicalOrigin(rightPath) {
		return true
	}
	if rightSource != "" && logicalOrigin(rightSource) == logicalOrigin(leftPath) {
		return true
	}
	return false
}

// logicalOrigin reduces a path to its logical container so that
// "doc.docx!word/document.xml" and "doc.docx!docProps/core.xml" share an origin.
func logicalOrigin(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	if index := strings.Index(value, "!"); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(value), "/"))
}

// mergeLogicalCredential folds two records for the same logical credential into
// one. Confirmed outranks Review, the strongest validation basis is kept, all
// evidence/provenance is retained, and non-empty identity/domain metadata is
// never discarded.
func mergeLogicalCredential(existing, incoming Candidate) Candidate {
	strong := existing
	weak := incoming
	if existing.Verification != Confirmed && incoming.Verification == Confirmed {
		strong, weak = incoming, existing
	}

	merged := strong
	merged.Verification = strong.Verification
	if merged.Verification != Confirmed && weak.Verification == Confirmed {
		merged.Verification = Confirmed
	}
	merged.ValidationBasis = firstNonEmptyString(strong.ValidationBasis, weak.ValidationBasis)
	merged.Identity = firstNonEmptyString(strong.Identity, weak.Identity)
	merged.Domain = firstNonEmptyString(strong.Domain, weak.Domain)
	merged.Source = firstNonEmptyString(strong.Source, weak.Source)
	merged.Path = firstNonEmptyString(strong.Path, weak.Path)
	merged.Host = firstNonEmptyString(strong.Host, weak.Host)
	merged.Share = firstNonEmptyString(strong.Share, weak.Share)
	merged.Container = firstNonEmptyString(strong.Container, weak.Container)
	merged.RID = firstNonZero(strong.RID, weak.RID)
	merged.SID = firstNonEmptyString(strong.SID, weak.SID)
	merged.AccountType = firstNonEmptyString(strong.AccountType, weak.AccountType)
	merged.Disabled = strong.Disabled || weak.Disabled
	merged.Encrypted = strong.Encrypted || weak.Encrypted
	merged.Evidence = mergeEvidence(strong.Evidence, weak.Evidence)
	if merged.Verification == Confirmed {
		// The merged record is confirmed; a weaker path's uncertainty notes no
		// longer describe it, but its evidence above is retained.
		merged.ReviewReasons = nil
	} else {
		merged.ReviewReasons = mergeStrings(strong.ReviewReasons, weak.ReviewReasons)
	}
	return merged
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
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

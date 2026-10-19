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

// Material separates actionable secret material from credential-related
// correlation evidence. "Confirmed" alone only means the record survived
// semantic validation; it does not prove that a secret value was recovered, so
// the ledger needs this second, stricter distinction before a row may be
// presented as a recovered credential.
type Material string

const (
	// MaterialSecret marks a record that carries actual secret material: a
	// recovered or explicit password, token, key, hash or connection secret.
	MaterialSecret Material = "secret"
	// MaterialCorrelation marks a credential-related record that carries no
	// secret type of its own: an identity observation, a deployment or artifact
	// marker, or a supporting correlation record.
	MaterialCorrelation Material = "correlation"
)

// secretCredentialTypes are the credential types that denote a concrete secret
// value. A record typed by anything else (for example a "credential indicator"
// or a group label) is correlation evidence rather than recovered secret
// material.
var secretCredentialTypes = map[string]struct{}{
	"password":          {},
	"passwd":            {},
	"pwd":               {},
	"passord":           {},
	"secret":            {},
	"shared_secret":     {},
	"client_secret":     {},
	"api_key":           {},
	"apikey":            {},
	"api_secret":        {},
	"access_key":        {},
	"secret_key":        {},
	"token":             {},
	"bearer_token":      {},
	"access_token":      {},
	"session_token":     {},
	"connection_string": {},
	"dsn":               {},
	"private_key":       {},
	"nt_hash":           {},
	"netntlmv1":         {},
	"netntlmv2":         {},
	"hash":              {},
	"certificate":       {},
}

// IsHashCredentialType reports whether a credential carries hash or
// challenge-response material. This is a presentation classification; the
// underlying credential type remains stable for persistence and exports.
func IsHashCredentialType(credentialType string) bool {
	switch strings.ToLower(strings.TrimSpace(credentialType)) {
	case "hash", "nt_hash", "netntlmv1", "netntlmv2":
		return true
	default:
		return false
	}
}

// CredentialPresentationLabel returns the operator-facing broad material
// class without changing the stored credential type.
func CredentialPresentationLabel(credentialType string) string {
	if IsHashCredentialType(credentialType) {
		return "HASH"
	}
	return "CREDENTIAL"
}

// CredentialTypeDisplayName returns a concise human-readable material type.
func CredentialTypeDisplayName(credentialType string) string {
	switch strings.ToLower(strings.TrimSpace(credentialType)) {
	case "nt_hash":
		return "NT hash"
	case "hash":
		return "Hash"
	case "netntlmv1":
		return "NetNTLMv1"
	case "netntlmv2":
		return "NetNTLMv2"
	default:
		return credentialType
	}
}

// IsSecretMaterialType reports whether a credential type denotes a concrete
// secret value rather than a credential-related category or correlation label.
func IsSecretMaterialType(credentialType string) bool {
	_, ok := secretCredentialTypes[strings.ToLower(strings.TrimSpace(credentialType))]
	return ok
}

// classifyMaterial reports whether a stored record carries actual secret
// material. A record is secret material only when it is typed as a concrete
// secret and holds a value; a credential-like record type (identity marker,
// deployment indicator, artifact correlation) is supporting evidence instead.
func classifyMaterial(candidate Candidate) Material {
	if !IsSecretMaterialType(candidate.CredentialType) {
		return MaterialCorrelation
	}
	if strings.TrimSpace(candidate.Value) == "" {
		return MaterialCorrelation
	}
	return MaterialSecret
}

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
	Occurrences     int
	Locations       []string
	Material        Material
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
	Occurrences     int          `json:"occurrences,omitempty"`
	Locations       []string     `json:"locations,omitempty"`
	Material        Material     `json:"material,omitempty"`
	ValidationBasis string       `json:"validation_basis,omitempty"`
	ReviewReasons   []string     `json:"review_reasons,omitempty"`
	Evidence        []Evidence   `json:"evidence,omitempty"`
}

type Report struct {
	CandidatesAnalyzed     int             `json:"candidates_analyzed"`
	SuppressedPlaceholders int             `json:"suppressed_placeholders"`
	SuppressedWeakReview   int             `json:"suppressed_weak_review"`
	Confirmed              []SafeCandidate `json:"confirmed,omitempty"`
	Review                 []SafeCandidate `json:"review,omitempty"`
	DuplicatesMerged       int             `json:"duplicates_merged"`
	Candidates             []Candidate     `json:"-"`
}

type analyzedCandidate struct {
	Candidate
	key string
}

func Analyze(candidates []Candidate) Report {
	report := Report{}
	merged := make(map[string]analyzedCandidate)
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.CredentialType) == "" {
			continue
		}
		// A record explicitly marked as correlation evidence describes an
		// identity, artifact or correlation observation rather than a secret, so
		// it may legitimately carry no value. Everything else must hold a value
		// to be credential material at all.
		if strings.TrimSpace(candidate.Value) == "" && candidate.Material != MaterialCorrelation {
			continue
		}
		report.CandidatesAnalyzed++
		if reason, suppressed := SuppressionReason(candidate); suppressed {
			if reason == "placeholder" {
				report.SuppressedPlaceholders++
			} else {
				report.SuppressedWeakReview++
			}
			continue
		}
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

// SuppressionReason applies the authoritative candidate-quality decision used
// by the credential ledger. Raw candidates may still be persisted for audit
// provenance, but a suppressed candidate must not be presented as recovered
// credential material by search or exports.
func SuppressionReason(candidate Candidate) (string, bool) {
	if strings.TrimSpace(candidate.Value) == "" && candidate.Material != MaterialCorrelation {
		return "empty_value", true
	}
	if _, placeholder := PlaceholderReason(candidate.Value); placeholder {
		return "placeholder", true
	}
	if _, weak := reviewCandidateLacksEvidence(candidate); weak {
		return "weak_review", true
	}
	return "", false
}

// SameLogicalCredential exposes the analysis ledger's equivalence policy to
// presentation layers that project persisted candidates. It deliberately keeps
// different users, types, values, and unrelated origins separate.
func SameLogicalCredential(left, right Candidate) bool {
	return sameLogicalCredential(left, right)
}

func candidateKey(candidate Candidate) string {
	return strings.ToLower(candidate.CredentialType) + "\x00" + strings.ToLower(candidate.Domain) + "\x00" + strings.ToLower(candidate.Identity) + "\x00" + candidate.Value
}

// reviewCandidateLacksEvidence reports whether a review candidate carries no
// meaningful credential evidence. Such a candidate is a vague "maybe
// credential" value: it has no identity, comes from no explicit password
// assignment, resolves to no structured credential relationship and has no
// token/API-key shape.
//
// Confirmed candidates are never affected: recovered secrets, structured
// credential objects, validated connection strings and inspector findings all
// arrive confirmed and keep their place in the ledger.
func reviewCandidateLacksEvidence(candidate Candidate) (string, bool) {
	if candidate.Verification == Confirmed {
		return "", false
	}
	credentialType := strings.ToLower(strings.TrimSpace(candidate.CredentialType))
	switch credentialType {
	case "private_key", "nt_hash", "netntlmv1", "netntlmv2", "certificate", "connection_string":
		// Recovered or composite material carries its own evidence.
		return "", false
	case "password":
		// A password alias is an explicit credential assignment; this holds even
		// when the identity is unknown and the value is weak, because a weak
		// password is still exactly what the operator needs to see.
		return "", false
	}
	if identity := strings.TrimSpace(candidate.Identity); identity != "" && !IsPlaceholderIdentity(identity) {
		return "", false
	}
	if _, ok := TokenSecretValueShape(candidate.Value); ok {
		return "", false
	}
	return "no identity, explicit password assignment, structured credential relationship or token shape", true
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
	merged.Occurrences = strong.Occurrences + weak.Occurrences
	merged.Locations = uniqueSorted(append(append([]string{}, strong.Locations...), weak.Locations...))
	merged.RID = firstNonZero(strong.RID, weak.RID)
	merged.SID = firstNonEmptyString(strong.SID, weak.SID)
	merged.AccountType = firstNonEmptyString(strong.AccountType, weak.AccountType)
	merged.Disabled = strong.Disabled || weak.Disabled
	merged.Encrypted = strong.Encrypted || weak.Encrypted
	merged.Evidence = mergeEvidence(strong.Evidence, weak.Evidence)
	// The material class follows the merged record's type and value, which are
	// identical for logically equivalent records.
	merged.Material = classifyMaterial(merged)
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
	candidate.Material = classifyMaterial(candidate)
	if candidate.Occurrences <= 0 {
		candidate.Occurrences = 1
	}
	// Every distinct observation location is retained so that deduplication
	// never drops where a credential was found.
	locations := append([]string{}, candidate.Locations...)
	if location := candidateProvenance(candidate); location != "" {
		locations = append(locations, location)
	}
	candidate.Locations = uniqueSorted(locations)
	return candidate
}

func toSafe(candidate Candidate) SafeCandidate {
	return SafeCandidate{
		Verification: candidate.Verification, CredentialType: candidate.CredentialType,
		Identity: candidate.Identity, Domain: candidate.Domain, ValuePresent: candidate.Value != "",
		RID: candidate.RID, SID: candidate.SID, AccountType: candidate.AccountType, Disabled: candidate.Disabled, Encrypted: candidate.Encrypted,
		Source: candidate.Source, Host: candidate.Host, Share: candidate.Share, Path: candidate.Path,
		Container: candidate.Container, Occurrences: candidate.Occurrences, Locations: append([]string{}, candidate.Locations...),
		Material: classifyMaterial(candidate), ValidationBasis: candidate.ValidationBasis,
		ReviewReasons: append([]string{}, candidate.ReviewReasons...), Evidence: append([]Evidence{}, candidate.Evidence...),
	}
}

// Provenance renders one observation location as a single operator-facing
// string. A UNC-style form is used whenever host/share are known; logical
// container members stay joined with "!" so an archive member is never shown as
// a bare loose file.
func Provenance(host, share, path, container string) string {
	path = strings.TrimSpace(path)
	container = strings.TrimSpace(container)
	if container != "" && container != path && !strings.Contains(path, "!") {
		if path == "" {
			path = container
		} else {
			path = container + "!" + path
		}
	}
	if path == "" {
		return ""
	}
	outer, members := splitContainerPath(path)
	outer = strings.ReplaceAll(outer, "/", `\`)
	if len(members) > 0 {
		path = outer + "!" + strings.Join(members, "!")
	} else {
		path = outer
	}
	host, share = strings.TrimSpace(host), strings.TrimSpace(share)
	if host == "" && share == "" {
		return path
	}
	if !strings.HasPrefix(path, `\`) {
		path = `\` + path
	}
	return `\\` + valueOrDashString(host) + `\` + valueOrDashString(share) + path
}

// candidateProvenance renders the location carried directly on a candidate.
func candidateProvenance(candidate Candidate) string {
	return Provenance(candidate.Host, candidate.Share, candidate.Path, candidate.Container)
}

// splitContainerPath separates the outer file path from logical container
// members joined with "!" (for example "backup.zip!docs/settings.ini").
func splitContainerPath(value string) (string, []string) {
	parts := strings.Split(value, "!")
	if len(parts) == 1 {
		return value, nil
	}
	return parts[0], parts[1:]
}

func valueOrDashString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
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

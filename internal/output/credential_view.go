package output

import (
	"strconv"
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// maxReviewRows bounds the number of review rows rendered into the HTML report.
// The underlying review set is never deleted: the JSON export and the explicit
// sensitive creds export still carry every record.
const maxReviewRows = 200

// credentialReportView is the operator-facing projection of the credential
// analysis. It carries only non-sensitive metadata (no secret values) and adds
// the provenance and finding linkage the raw analysis model does not express.
type credentialReportView struct {
	Confirmed              []credentialRow
	Review                 []credentialRow
	RecoveredSecrets       int
	ReviewTotal            int
	ReviewTruncated        bool
	ReviewRendered         int
	SuppressedPlaceholders int
	SuppressedWeakReview   int
	SuppressedTotal        int
}

// credentialRow is one operator-facing credential row.
type credentialRow struct {
	Identity        string
	Type            string
	Host            string
	Share           string
	Provenance      string
	Locations       []string
	Occurrences     int
	OccurrenceLabel string
	Validation      string
	ReviewReasons   string
	Anchor          string
	Status          string
}

func buildCredentialReportView(analysis credentialanalysis.Report, groups ...[]htmlCategoryGroup) credentialReportView {
	index := map[string]string{}
	for _, group := range groups {
		indexFindingAnchors(group, index)
	}
	view := credentialReportView{
		SuppressedPlaceholders: analysis.SuppressedPlaceholders,
		SuppressedWeakReview:   analysis.SuppressedWeakReview,
		SuppressedTotal:        analysis.SuppressedPlaceholders + analysis.SuppressedWeakReview,
	}
	for _, candidate := range analysis.Confirmed {
		row := credentialRowFromCandidate(candidate, index)
		if row.Validation == validationCryptographic {
			view.RecoveredSecrets++
		}
		view.Confirmed = append(view.Confirmed, row)
	}
	view.ReviewTotal = len(analysis.Review)
	for i, candidate := range analysis.Review {
		if i >= maxReviewRows {
			view.ReviewTruncated = true
			break
		}
		view.Review = append(view.Review, credentialRowFromCandidate(candidate, index))
	}
	view.ReviewRendered = len(view.Review)
	return view
}

func credentialRowFromCandidate(candidate credentialanalysis.SafeCandidate, index map[string]string) credentialRow {
	row := credentialRow{
		Identity:        candidate.Identity,
		Type:            candidate.CredentialType,
		Host:            candidate.Host,
		Share:           candidate.Share,
		Locations:       append([]string{}, candidate.Locations...),
		Occurrences:     candidate.Occurrences,
		OccurrenceLabel: strconv.Itoa(maxIntValue(candidate.Occurrences, 1)),
		Validation:      validationBasisLabel(candidate.ValidationBasis),
		ReviewReasons:   strings.Join(candidate.ReviewReasons, "; "),
	}
	if row.Occurrences <= 0 {
		row.Occurrences = 1
	}
	row.Provenance = credentialanalysis.Provenance(candidate.Host, candidate.Share, candidate.Path, candidate.Container)
	if row.Provenance == "" && len(row.Locations) > 0 {
		row.Provenance = row.Locations[0]
	}
	row.Anchor = lookupCredentialAnchor(candidate, index)
	if row.Anchor == "" {
		row.Status = credentialStatusText(candidate)
	}
	return row
}

func credentialStatusText(candidate credentialanalysis.SafeCandidate) string {
	parts := []string{"no corresponding finding card"}
	switch {
	case candidate.Container != "" || strings.Contains(candidate.Path, "!"):
		parts = append(parts, "archive member")
	case validationBasisLabel(candidate.ValidationBasis) == validationStructured:
		parts = append(parts, "structured config credential")
	case validationBasisLabel(candidate.ValidationBasis) == validationCryptographic:
		parts = append(parts, "recovered credential store material")
	default:
		parts = append(parts, "harvested independently")
	}
	return strings.Join(parts, " · ")
}

// lookupCredentialAnchor finds a deterministically matching finding card for a
// credential candidate. Matching is by host, share and file path, so a link is
// only produced when a corresponding card genuinely exists.
func lookupCredentialAnchor(candidate credentialanalysis.SafeCandidate, index map[string]string) string {
	keys := []string{provenanceKey(candidate.Host, candidate.Share, candidate.Path)}
	for _, evidence := range candidate.Evidence {
		keys = append(keys, provenanceKey(candidate.Host, candidate.Share, evidence.Path))
	}
	if candidate.Container != "" && !strings.Contains(candidate.Path, "!") {
		keys = append(keys, provenanceKey(candidate.Host, candidate.Share, candidate.Container+"!"+candidate.Path))
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if anchor, ok := index[key]; ok {
			return anchor
		}
	}
	return ""
}

func indexFindingAnchors(groups []htmlCategoryGroup, index map[string]string) {
	for _, group := range groups {
		for _, item := range group.Findings {
			if !isCredentialRelatedFinding(item.Finding) {
				continue
			}
			anchor := findingAnchor(item.Finding)
			record := func(host, share, path string) {
				if key := provenanceKey(host, share, path); key != "" {
					index[key] = anchor
				}
			}
			record(item.Finding.Host, item.Finding.Share, item.Finding.FilePath)
			for _, duplicate := range item.Duplicates {
				record(duplicate.Host, duplicate.Share, duplicate.FilePath)
			}
		}
	}
}

// isCredentialRelatedFinding reports whether a finding card plausibly documents
// the same credential material. The check only gates whether an existing card is
// eligible to be linked; it never creates a link on its own.
func isCredentialRelatedFinding(f scanner.Finding) bool {
	rule := strings.ToLower(strings.TrimSpace(f.RuleID))
	for _, token := range []string{
		"credential", "password", "passord", "secret", "token", "private_key",
		"connection_string", "dsn", "aws", "ntds", "dpapi",
		"browser", "vault", "wincred", "sqlite", "deployment",
	} {
		if strings.Contains(rule, token) {
			return true
		}
	}
	switch strings.ToLower(strings.TrimSpace(f.Category)) {
	case "credentials", "crypto", "database-access", "deployment", "windows-credentials", "browser-credentials":
		return true
	default:
		return false
	}
}

// findingAnchor derives a stable, collision-resistant anchor id for a finding
// card from its rule and location.
func findingAnchor(f scanner.Finding) string {
	key := strings.Join([]string{
		strings.ToLower(strings.TrimSpace(f.RuleID)),
		strings.ToLower(strings.TrimSpace(f.Host)),
		strings.ToLower(strings.TrimSpace(f.Share)),
		normalizeProvenancePath(f.FilePath),
	}, "|")
	anchor := "finding-" + slug(key)
	const maxAnchorLength = 120
	if len(anchor) > maxAnchorLength {
		anchor = strings.Trim(anchor[:maxAnchorLength], "-")
	}
	return anchor
}

func provenanceKey(host, share, path string) string {
	path = normalizeProvenancePath(path)
	if path == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strings.ToLower(strings.TrimSpace(share)) + "|" + path
}

func normalizeProvenancePath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	path = strings.ReplaceAll(path, `\`, "/")
	path = strings.TrimPrefix(path, "./")
	path = strings.Trim(path, "/")
	return path
}

const (
	validationCryptographic = "cryptographically recovered"
	validationStructured    = "structurally parsed explicit credential"
	validationContextual    = "contextual candidate"
)

// validationBasisLabel renders a raw validation basis as truthful,
// operator-facing wording. A parsed configuration credential is never described
// as cryptographic recovery.
func validationBasisLabel(basis string) string {
	lower := strings.ToLower(strings.TrimSpace(basis))
	switch {
	case lower == "":
		return validationContextual
	case containsAnySubstring(lower, "cryptograph", "ntds", "private_key", "recovery", "sam", "lsa", "dpapi", "browser", "kerberos"):
		return validationCryptographic
	case containsAnySubstring(lower, "structured", "configuration", "xml", "json", "yaml", "deployment", "windows", "explicit", "connection_string", "dsn", "object", "pair", "section", "record", "field"):
		return validationStructured
	default:
		return validationContextual
	}
}

func containsAnySubstring(value string, parts ...string) bool {
	for _, part := range parts {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

func maxIntValue(a, b int) int {
	if a > b {
		return a
	}
	return b
}

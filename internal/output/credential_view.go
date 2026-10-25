package output

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

// maxReviewRows bounds the number of review rows rendered into the HTML report.
// The underlying review set is never deleted: the JSON export and the explicit
// sensitive creds export still carry every record.
const maxReviewRows = 200

const credentialRowChannelBuffer = 32

// maxCredentialExtraLocations bounds how many additional locations one credential
// row renders inside its collapsed provenance block. A single credential can be
// observed in hundreds of files; the row stays readable and the complete list
// remains available in the JSON export and the sensitive creds export.
const maxCredentialExtraLocations = 40

// credentialReportView is the operator-facing projection of the credential
// analysis. It carries recovered values because the HTML report is a sensitive
// security-assessment artifact.
type credentialReportView struct {
	Confirmed              any
	Supporting             any
	Review                 any
	ConfirmedCount         int
	SupportingCount        int
	ReviewCount            int
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
	Identity           string
	Type               string
	Value              string
	Host               string
	Share              string
	Provenance         string
	ExtraLocations     []string
	ExtraLocationTotal int
	Occurrences        int
	OccurrenceLabel    string
	Validation         string
	ReviewReasons      string
	Anchor             string
	Status             string
}

func buildCredentialReportView(analysis credentialanalysis.Report, groups ...[]htmlCategoryGroup) credentialReportView {
	index := map[string]string{}
	for _, group := range groups {
		indexFindingAnchors(group, index)
	}
	return buildCredentialReportViewWithResolver(analysis, func(candidate credentialanalysis.SafeCandidate) string {
		return lookupCredentialAnchor(candidate, index)
	})
}

type credentialAnchorResolver func(credentialanalysis.SafeCandidate) string

func buildCredentialReportViewWithResolver(analysis credentialanalysis.Report, resolve credentialAnchorResolver) credentialReportView {
	view := credentialReportView{
		SuppressedPlaceholders: analysis.SuppressedPlaceholders,
		SuppressedWeakReview:   analysis.SuppressedWeakReview,
		SuppressedTotal:        analysis.SuppressedPlaceholders + analysis.SuppressedWeakReview,
	}
	var confirmed, supporting, review []credentialRow
	for _, candidate := range analysis.Confirmed {
		row := credentialRowFromCandidateResolver(candidate, candidateValue(analysis.Candidates, candidate), resolve)
		// Only records that carry real secret material belong in the actionable
		// credential table. Credential-related records without a secret type stay
		// in the supporting hierarchy below the findings.
		if candidate.Material == credentialanalysis.MaterialCorrelation {
			supporting = append(supporting, row)
			view.SupportingCount++
			continue
		}
		if row.Validation == validationCryptographic {
			view.RecoveredSecrets++
		}
		confirmed = append(confirmed, row)
		view.ConfirmedCount++
	}
	view.ReviewTotal = len(analysis.Review)
	view.ReviewCount = view.ReviewTotal
	for i, candidate := range analysis.Review {
		if i >= maxReviewRows {
			view.ReviewTruncated = true
			break
		}
		review = append(review, credentialRowFromCandidateResolver(candidate, candidateValue(analysis.Candidates, candidate), resolve))
	}
	view.Confirmed, view.Supporting, view.Review = confirmed, supporting, review
	view.ReviewRendered = len(review)
	return view
}

// buildPersistedCredentialReportView performs a bounded count pass, then
// streams rows from compact persisted records. It never calls the legacy
// merger Iterate method and never reconstructs a complete candidate/report
// slice. The returned error channel covers the rendering pass.
func buildPersistedCredentialReportView(ctx context.Context, analysis *credentialanalysis.PersistedAnalysis, resolve credentialAnchorResolver) (credentialReportView, <-chan error, error) {
	view := credentialReportView{}
	stats := analysis.Stats()
	view.SuppressedPlaceholders = stats.SuppressedPlaceholders
	view.SuppressedWeakReview = stats.SuppressedWeakReview
	view.SuppressedTotal = stats.SuppressedPlaceholders + stats.SuppressedWeakReview
	if err := analysis.IterateRecords(ctx, func(record credentialanalysis.PersistedMergedRecord) error {
		candidate := record.Candidate
		if candidate.Verification != credentialanalysis.Confirmed {
			view.ReviewCount++
			return nil
		}
		if candidate.Material == credentialanalysis.MaterialCorrelation {
			view.SupportingCount++
			return nil
		}
		view.ConfirmedCount++
		if validationBasisLabel(candidate.ValidationBasis) == validationCryptographic {
			view.RecoveredSecrets++
		}
		return nil
	}); err != nil {
		return view, nil, err
	}
	view.ReviewTotal = view.ReviewCount
	view.ReviewRendered = minIntValue(view.ReviewCount, maxReviewRows)
	view.ReviewTruncated = view.ReviewCount > maxReviewRows
	confirmed := make(chan credentialRow, credentialRowChannelBuffer)
	supporting := make(chan credentialRow, credentialRowChannelBuffer)
	review := make(chan credentialRow, credentialRowChannelBuffer)
	errs := make(chan error, 3)
	view.Confirmed, view.Supporting, view.Review = confirmed, supporting, review
	var resolveMu sync.Mutex
	serializedResolve := func(candidate credentialanalysis.SafeCandidate) string {
		resolveMu.Lock()
		defer resolveMu.Unlock()
		return resolve(candidate)
	}
	var producers sync.WaitGroup
	start := func(out chan<- credentialRow, matches func(credentialanalysis.PersistedMergedRecord) bool, limit int) {
		producers.Add(1)
		go func() {
			defer producers.Done()
			defer close(out)
			emitted := 0
			err := analysis.IterateRecords(ctx, func(record credentialanalysis.PersistedMergedRecord) error {
				if !matches(record) || (limit > 0 && emitted >= limit) {
					return nil
				}
				row, err := persistedCredentialRow(ctx, analysis, record, serializedResolve)
				if err != nil {
					return err
				}
				select {
				case out <- row:
					emitted++
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	start(confirmed, func(record credentialanalysis.PersistedMergedRecord) bool {
		return record.Candidate.Verification == credentialanalysis.Confirmed && record.Candidate.Material != credentialanalysis.MaterialCorrelation
	}, 0)
	start(supporting, func(record credentialanalysis.PersistedMergedRecord) bool {
		return record.Candidate.Verification == credentialanalysis.Confirmed && record.Candidate.Material == credentialanalysis.MaterialCorrelation
	}, 0)
	start(review, func(record credentialanalysis.PersistedMergedRecord) bool {
		return record.Candidate.Verification != credentialanalysis.Confirmed
	}, maxReviewRows)
	go func() {
		producers.Wait()
		close(errs)
	}()
	return view, errs, nil
}

func minIntValue(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func persistedCredentialRow(ctx context.Context, analysis *credentialanalysis.PersistedAnalysis, record credentialanalysis.PersistedMergedRecord, resolve credentialAnchorResolver) (credentialRow, error) {
	candidate := record.Candidate
	safe := credentialanalysis.SafeCandidateForPersistence(candidate)
	anchor := resolve(safe)
	if anchor == "" {
		var cursor credentialanalysis.EvidenceCursor
		for {
			var more bool
			var err error
			cursor, more, err = analysis.IterateEvidencePage(ctx, record.ID, cursor, 32, func(evidence credentialanalysis.Evidence) error {
				probe := safe
				probe.Evidence = []credentialanalysis.Evidence{evidence}
				if found := resolve(probe); found != "" {
					anchor = found
				}
				return nil
			})
			if err != nil {
				return credentialRow{}, err
			}
			if anchor != "" || !more {
				break
			}
		}
	}
	row := credentialRowFromCandidateResolver(safe, candidate.Value, func(credentialanalysis.SafeCandidate) string { return anchor })
	row.ExtraLocationTotal = maxIntValue(record.LocationCount-1, 0)
	return row, nil
}

func credentialRowFromCandidate(candidate credentialanalysis.SafeCandidate, value string, index map[string]string) credentialRow {
	return credentialRowFromCandidateResolver(candidate, value, func(candidate credentialanalysis.SafeCandidate) string {
		return lookupCredentialAnchor(candidate, index)
	})
}

func credentialRowFromCandidateResolver(candidate credentialanalysis.SafeCandidate, value string, resolve credentialAnchorResolver) credentialRow {
	row := credentialRow{
		Identity:        candidate.Identity,
		Type:            candidate.CredentialType,
		Value:           credentialDisplayValue(value),
		Host:            candidate.Host,
		Share:           candidate.Share,
		Occurrences:     candidate.Occurrences,
		OccurrenceLabel: strconv.Itoa(maxIntValue(candidate.Occurrences, 1)),
		Validation:      validationBasisLabel(candidate.ValidationBasis),
		ReviewReasons:   strings.Join(candidate.ReviewReasons, "; "),
	}
	if row.Occurrences <= 0 {
		row.Occurrences = 1
	}
	row.Provenance = credentialanalysis.Provenance(candidate.Host, candidate.Share, candidate.Path, candidate.Container)
	locations := append([]string{}, candidate.Locations...)
	if row.Provenance == "" && len(locations) > 0 {
		row.Provenance, locations = locations[0], locations[1:]
	}
	extra := make([]string, 0, len(locations))
	for _, location := range locations {
		if location == "" || strings.EqualFold(location, row.Provenance) {
			continue
		}
		extra = append(extra, location)
	}
	row.ExtraLocationTotal = len(extra)
	if len(extra) > maxCredentialExtraLocations {
		extra = extra[:maxCredentialExtraLocations]
	}
	row.ExtraLocations = extra
	if resolve != nil {
		row.Anchor = resolve(candidate)
	}
	if row.Anchor == "" {
		row.Status = credentialStatusText(candidate)
	}
	return row
}

func candidateValue(candidates []credentialanalysis.Candidate, safe credentialanalysis.SafeCandidate) string {
	for _, candidate := range candidates {
		if !sameCredentialField(candidate.CredentialType, safe.CredentialType) ||
			!sameCredentialField(candidate.Identity, safe.Identity) ||
			!sameCredentialField(candidate.Domain, safe.Domain) ||
			!sameCredentialField(candidate.Host, safe.Host) ||
			!sameCredentialField(candidate.Share, safe.Share) ||
			!sameCredentialField(candidate.Path, safe.Path) ||
			!sameCredentialField(candidate.Container, safe.Container) ||
			candidate.Value == "" {
			continue
		}
		return candidate.Value
	}
	return ""
}

func sameCredentialField(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func credentialDisplayValue(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\x00", "\n"))
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

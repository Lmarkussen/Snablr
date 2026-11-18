package seed

import (
	"fmt"
	"sort"
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/credentialaudit"
	"snablr/internal/scanner"
)

// anyHost replaces host identities when a manifest and a scan name the same
// targets differently (for example the seeder wrote via an IP address and the
// scan reported a hostname). Matching then uses share and path only.
const anyHost = "*"

// PairExpectation identifies one expected username/password pair without
// carrying the expected password into reports.
type PairExpectation struct {
	ID       string
	Host     string
	Share    string
	Path     string
	Username string
}

// PairVerificationReport compares expected credential pairs from the seed
// manifest with credential material recovered by the scan.
type PairVerificationReport struct {
	EntriesWithPairs int
	ExpectedPairs    int
	MatchedPairs     int
	Missing          []PairExpectation
}

// alignVerificationHosts reports whether manifest and finding hosts overlap.
// When they do not, it rewrites both sides to anyHost so verification falls
// back to share+path identity instead of reporting every item as missed.
func alignVerificationHosts(manifest *Manifest, findings []scanner.Finding) ([]scanner.Finding, bool) {
	manifestHosts := make(map[string]struct{})
	for _, entry := range manifest.Entries {
		if host := normalizeVerifyValue(entry.Host); host != "" {
			manifestHosts[host] = struct{}{}
		}
	}
	if len(manifestHosts) == 0 || len(findings) == 0 {
		return findings, true
	}
	for _, finding := range findings {
		if _, ok := manifestHosts[normalizeVerifyValue(finding.Host)]; ok {
			return findings, true
		}
	}
	aligned := make([]scanner.Finding, len(findings))
	for i, finding := range findings {
		finding.Host = anyHost
		aligned[i] = finding
	}
	entries := make([]SeedManifestEntry, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		if strings.TrimSpace(entry.Host) != "" {
			entry.Host = anyHost
		}
		entries[i] = entry
	}
	manifest.Entries = entries
	return aligned, false
}

// countNotWrittenEntries returns how many manifest entries were never written
// to the target (dry-run manifests). Verification results for them only
// reflect whatever already existed on the share.
func countNotWrittenEntries(manifest Manifest) int {
	count := 0
	for _, entry := range manifest.Entries {
		if strings.EqualFold(strings.TrimSpace(entry.Status), "dry-run") {
			count++
		}
	}
	return count
}

// expectedPairsForEntry returns the explicit pairs an entry expects: the
// detailed pair list when present, otherwise the single expected
// username/password.
func expectedPairsForEntry(entry SeedManifestEntry) []credentialaudit.ExpectedPair {
	source := pairSourceKey(entry.Host, entry.Share, entry.Path)
	if source == "" {
		return nil
	}
	base := entry.FixtureID
	if base == "" {
		base = source
	}
	pairs := make([]credentialaudit.ExpectedPair, 0, len(entry.ExpectedPairsDetail))
	for index, detail := range entry.ExpectedPairsDetail {
		if detail.Username == "" || detail.Password == "" {
			continue
		}
		id := detail.ID
		if id == "" {
			id = fmt.Sprintf("%d", index)
		}
		pairs = append(pairs, credentialaudit.ExpectedPair{ID: base + "#" + id, SourcePath: source, Username: detail.Username, Password: detail.Password})
	}
	if len(pairs) == 0 && entry.ExpectedUsername != "" && entry.ExpectedPassword != "" {
		pairs = append(pairs, credentialaudit.ExpectedPair{ID: base, SourcePath: source, Username: entry.ExpectedUsername, Password: entry.ExpectedPassword})
	}
	return pairs
}

// VerifyCredentialPairs checks that every explicitly expected username and
// password pair in the manifest was recovered from the same source file.
// matchHosts must be false when the manifest and scan name hosts differently.
func VerifyCredentialPairs(manifest Manifest, credentials []credentialanalysis.Candidate, matchHosts bool) PairVerificationReport {
	report := PairVerificationReport{}
	expected := make([]credentialaudit.ExpectedPair, 0)
	byID := make(map[string]PairExpectation)
	for _, entry := range manifest.Entries {
		if !matchHosts && strings.TrimSpace(entry.Host) != "" {
			entry.Host = anyHost
		}
		pairs := expectedPairsForEntry(entry)
		if len(pairs) == 0 {
			continue
		}
		report.EntriesWithPairs++
		for _, pair := range pairs {
			expected = append(expected, pair)
			byID[pair.ID] = PairExpectation{ID: pair.ID, Host: entry.Host, Share: entry.Share, Path: entry.Path, Username: pair.Username}
		}
	}
	report.ExpectedPairs = len(expected)
	if len(expected) == 0 {
		return report
	}

	observed := make([]credentialaudit.ObservedMaterial, 0, len(credentials))
	for index, candidate := range credentials {
		host := candidate.Host
		if !matchHosts {
			host = anyHost
		}
		source := pairSourceKey(host, candidate.Share, candidate.Path)
		if source == "" {
			continue
		}
		observed = append(observed, credentialaudit.ObservedMaterial{
			RowID:        fmt.Sprintf("%d", index),
			SourcePath:   source,
			MaterialType: candidate.CredentialType,
			Identity:     candidate.Identity,
			Value:        candidate.Value,
			Verification: string(candidate.Verification),
		})
	}

	comparison := credentialaudit.Compare(expected, observed)
	report.MatchedPairs = len(comparison.Matches)
	for _, id := range comparison.MissingIDs {
		report.Missing = append(report.Missing, byID[id])
	}
	sort.Slice(report.Missing, func(i, j int) bool {
		left, right := report.Missing[i], report.Missing[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.ID < right.ID
	})
	return report
}

// pairSourceKey identifies a physical source object. Archive members keep
// their "!member" suffix so credentialaudit can reduce both sides to the
// containing file consistently.
func pairSourceKey(host, share, path string) string {
	host = normalizeVerifyValue(host)
	share = normalizeVerifyValue(share)
	path = normalizeVerifyPath(path)
	if host == "" || share == "" || path == "" {
		return ""
	}
	return host + "|" + share + "|" + path
}

// PrintPairVerificationReport prints pair recall without expected passwords.
func PrintPairVerificationReport(report PairVerificationReport) {
	fmt.Println("\nCredential pair verification:")
	if report.ExpectedPairs == 0 {
		fmt.Println("- manifest has no explicit expected username/password pairs")
		return
	}
	recall := 100 * float64(report.MatchedPairs) / float64(report.ExpectedPairs)
	fmt.Printf("- entries with expected pairs: %d\n", report.EntriesWithPairs)
	fmt.Printf("- expected pairs matched: %d/%d (%.1f%%)\n", report.MatchedPairs, report.ExpectedPairs, recall)
	if len(report.Missing) > 0 {
		fmt.Println("\nMissing expected pairs (username shown, password omitted):")
		for _, item := range report.Missing {
			fmt.Printf("- %s/%s/%s user=%s id=%s\n", valueOrDash(item.Host), valueOrDash(item.Share), item.Path, valueOrDash(item.Username), item.ID)
		}
	}
}

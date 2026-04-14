package output

import (
	"fmt"
	"sort"
	"strings"

	"snablr/internal/scanner"
)

type reportFindingGroup struct {
	Canonical  scanner.Finding
	Duplicates []scanner.Finding
}

func groupDuplicateReportFindings(findings []scanner.Finding) []reportFindingGroup {
	if len(findings) == 0 {
		return nil
	}

	buckets := make(map[string][]scanner.Finding, len(findings))
	for _, finding := range findings {
		key := reportDuplicateGroupKey(finding)
		buckets[key] = append(buckets[key], finding)
	}

	groups := make([]reportFindingGroup, 0, len(buckets))
	for _, grouped := range buckets {
		canonical := selectCanonicalReportFinding(grouped)
		duplicateLocations := collectDuplicateLocations(grouped, canonical)
		groups = append(groups, reportFindingGroup{
			Canonical:  canonical,
			Duplicates: duplicateLocations,
		})
	}

	sort.Slice(groups, func(i, j int) bool {
		left := severityRank(groups[i].Canonical.Severity)
		right := severityRank(groups[j].Canonical.Severity)
		if left == right {
			if groups[i].Canonical.Host == groups[j].Canonical.Host {
				if groups[i].Canonical.Share == groups[j].Canonical.Share {
					return groups[i].Canonical.FilePath < groups[j].Canonical.FilePath
				}
				return groups[i].Canonical.Share < groups[j].Canonical.Share
			}
			return groups[i].Canonical.Host < groups[j].Canonical.Host
		}
		return left > right
	})

	return groups
}

func reportDuplicateGroupKey(f scanner.Finding) string {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	if strings.HasPrefix(ruleID, "correlation.") || strings.EqualFold(strings.TrimSpace(primarySignal(f)), "correlation") {
		return "correlated|" + reportFindingDedupKey(f)
	}

	material := strings.TrimSpace(reportFindingMaterialIdentity(f))
	if material == "" {
		return "exact|" + reportFindingDedupKey(f)
	}

	return strings.Join([]string{
		ruleID,
		strings.ToLower(strings.TrimSpace(f.Category)),
		strings.ToLower(strings.TrimSpace(primarySignal(f))),
		material,
	}, "|")
}

func reportFindingMaterialIdentity(f scanner.Finding) string {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	switch ruleID {
	case "awsinspect.content.credentials_bundle":
		values := parseAssignmentValues(joinNonEmpty(f.MatchedText, f.Context))
		accessKey := strings.TrimSpace(firstNonEmpty(values["aws_access_key_id"], values["access_key"], values["accesskey"]))
		secretKey := strings.TrimSpace(firstNonEmpty(values["aws_secret_access_key"], values["secret_key"], values["secretaccesskey"]))
		sessionToken := strings.TrimSpace(firstNonEmpty(values["aws_session_token"], values["session_token"]))
		profile := strings.TrimSpace(awsProfileName(f))
		if accessKey != "" || secretKey != "" {
			return fmt.Sprintf("aws|%s|%s|%s|%s", accessKey, secretKey, sessionToken, profile)
		}
	case "dbinspect.access.connection_string", "dbinspect.access.dsn":
		parsed := parseDatabaseCredential(firstNonEmpty(strings.TrimSpace(f.MatchedText), strings.TrimSpace(f.Context), strings.TrimSpace(f.Match)))
		if parsed.host != "" || parsed.database != "" || parsed.user != "" || parsed.password != "" || parsed.raw != "" {
			return fmt.Sprintf("db|%s|%s|%s|%s|%s", parsed.host, parsed.database, parsed.user, parsed.password, normalizeEvidenceIdentity(parsed.raw))
		}
	case "keyinspect.content.private_key_header":
		if value := normalizeEvidenceIdentity(firstNonEmpty(f.Context, f.Snippet, f.MatchedText, f.Match)); value != "" {
			return "key|" + value
		}
	}

	values := parseAssignmentValues(joinNonEmpty(f.MatchedText, f.Context, f.Match))
	if secretLabel, secretValue := bestSecretValue(values); secretValue != "" {
		account := firstNonEmpty(values["user"], values["username"], values["uid"], values["userid"], normalizePotentialAccount(f.PotentialAccount))
		context := firstNonEmpty(values["host"], values["server"], values["database"], values["dbname"], f.DatabaseTable, f.DatabaseColumn)
		return fmt.Sprintf("secret|%s|%s|%s|%s", secretLabel, secretValue, account, context)
	}

	if value := normalizeEvidenceIdentity(firstNonEmpty(f.MatchedText, f.Match, f.Context, f.Snippet)); value != "" {
		return "raw|" + value
	}

	return ""
}

func normalizeEvidenceIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.Join(strings.Fields(value), " ")
}

func selectCanonicalReportFinding(findings []scanner.Finding) scanner.Finding {
	best := findings[0]
	for _, candidate := range findings[1:] {
		if reportFindingPreferred(candidate, best) {
			best = candidate
		}
	}
	return best
}

func reportFindingPreferred(candidate, current scanner.Finding) bool {
	if candidate.Actionable != current.Actionable {
		return candidate.Actionable
	}
	if candidate.Correlated != current.Correlated {
		return candidate.Correlated
	}
	if candidate.ConfidenceScore != current.ConfidenceScore {
		return candidate.ConfidenceScore > current.ConfidenceScore
	}
	if severityRank(candidate.Severity) != severityRank(current.Severity) {
		return severityRank(candidate.Severity) > severityRank(current.Severity)
	}
	if len(strings.TrimSpace(candidate.Context)) != len(strings.TrimSpace(current.Context)) {
		return len(strings.TrimSpace(candidate.Context)) > len(strings.TrimSpace(current.Context))
	}
	if reportPathPreference(candidate) != reportPathPreference(current) {
		return reportPathPreference(candidate) > reportPathPreference(current)
	}
	return len(uncPath(candidate)) < len(uncPath(current))
}

func reportPathPreference(f scanner.Finding) int {
	score := 0
	if strings.TrimSpace(f.ArchivePath) == "" && !strings.Contains(f.FilePath, "!") {
		score += 2
	}
	if strings.TrimSpace(f.DatabaseFilePath) == "" {
		score++
	}
	return score
}

func collectDuplicateLocations(findings []scanner.Finding, canonical scanner.Finding) []scanner.Finding {
	seen := map[string]struct{}{
		reportLocationKey(canonical): {},
	}
	duplicates := make([]scanner.Finding, 0, len(findings)-1)
	for _, finding := range findings {
		key := reportLocationKey(finding)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		duplicates = append(duplicates, finding)
	}
	sort.Slice(duplicates, func(i, j int) bool {
		return uncPath(duplicates[i]) < uncPath(duplicates[j])
	})
	return duplicates
}

func reportLocationKey(f scanner.Finding) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(f.Host)),
		strings.ToLower(strings.TrimSpace(f.Share)),
		strings.ToLower(strings.TrimSpace(f.FilePath)),
		strings.ToLower(strings.TrimSpace(f.ArchivePath)),
		strings.ToLower(strings.TrimSpace(f.ArchiveMemberPath)),
		strings.ToLower(strings.TrimSpace(f.DatabaseFilePath)),
		strings.ToLower(strings.TrimSpace(f.DatabaseTable)),
		strings.ToLower(strings.TrimSpace(f.DatabaseColumn)),
	}, "|")
}

func duplicateScopeText(canonical scanner.Finding, duplicates []scanner.Finding) string {
	parts := []string{strings.TrimSpace(canonical.Host), strings.TrimSpace(canonical.Share)}
	for _, duplicate := range duplicates {
		parts = append(parts, strings.TrimSpace(duplicate.Host), strings.TrimSpace(duplicate.Share))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func duplicateSearchText(base string, duplicates []scanner.Finding) string {
	if len(duplicates) == 0 {
		return strings.TrimSpace(base)
	}
	parts := []string{strings.TrimSpace(base)}
	for _, duplicate := range duplicates {
		parts = append(parts, uncPath(duplicate), strings.TrimSpace(duplicate.FilePath), strings.TrimSpace(duplicate.ArchivePath), strings.TrimSpace(duplicate.ArchiveMemberPath))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

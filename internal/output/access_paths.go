package output

import (
	"path/filepath"
	"sort"
	"strings"

	"snablr/internal/scanner"
)

type accessPathSummary struct {
	Rank               int      `json:"rank"`
	RuleID             string   `json:"rule_id"`
	Type               string   `json:"type"`
	BaseType           string   `json:"base_type,omitempty"`
	Label              string   `json:"label"`
	WhyItMatters       string   `json:"why_it_matters"`
	AccessHint         string   `json:"access_hint,omitempty"`
	Severity           string   `json:"severity"`
	Confidence         string   `json:"confidence"`
	Category           string   `json:"category"`
	Host               string   `json:"host,omitempty"`
	Share              string   `json:"share,omitempty"`
	PrimaryPath        string   `json:"primary_path"`
	ExploitabilityScore int     `json:"exploitability_score"`
	PriorityTier       string   `json:"priority_tier"`
	Completeness       string   `json:"completeness,omitempty"`
	ArchiveDerived     bool     `json:"archive_derived,omitempty"`
	RelatedArtifacts   []string `json:"related_artifacts,omitempty"`
}

func buildAccessPathSummaries(findings []scanner.Finding) []accessPathSummary {
	summaries := make([]accessPathSummary, 0)
	for _, finding := range findings {
		if !finding.Correlated {
			continue
		}
		summary, ok := classifyAccessPath(finding)
		if !ok {
			continue
		}
		summaries = append(summaries, summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].ExploitabilityScore != summaries[j].ExploitabilityScore {
			return summaries[i].ExploitabilityScore > summaries[j].ExploitabilityScore
		}
		if severityRank(summaries[i].Severity) != severityRank(summaries[j].Severity) {
			return severityRank(summaries[i].Severity) > severityRank(summaries[j].Severity)
		}
		if len(summaries[i].RelatedArtifacts) != len(summaries[j].RelatedArtifacts) {
			return len(summaries[i].RelatedArtifacts) > len(summaries[j].RelatedArtifacts)
		}
		if summaries[i].Host != summaries[j].Host {
			return summaries[i].Host < summaries[j].Host
		}
		if summaries[i].Share != summaries[j].Share {
			return summaries[i].Share < summaries[j].Share
		}
		if summaries[i].PrimaryPath != summaries[j].PrimaryPath {
			return summaries[i].PrimaryPath < summaries[j].PrimaryPath
		}
		return summaries[i].RuleID < summaries[j].RuleID
	})
	for i := range summaries {
		summaries[i].Rank = i + 1
	}
	return summaries
}

func topAccessPaths(items []accessPathSummary, limit int) []accessPathSummary {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func classifyAccessPath(finding scanner.Finding) (accessPathSummary, bool) {
	base := accessPathClassification(strings.ToLower(strings.TrimSpace(finding.RuleID)), finding)
	if base.Type == "" {
		return accessPathSummary{}, false
	}
	score := base.Score + completenessBonus(base.Completeness) + archiveBonus(finding)
	if score > 100 {
		score = 100
	}

	summary := accessPathSummary{
		RuleID:              strings.TrimSpace(finding.RuleID),
		Type:                base.Type,
		BaseType:            base.BaseType,
		Label:               base.Label,
		WhyItMatters:        base.Why,
		AccessHint:          base.AccessHint,
		Severity:            strings.TrimSpace(finding.Severity),
		Confidence:          strings.TrimSpace(finding.Confidence),
		Category:            strings.TrimSpace(finding.Category),
		Host:                strings.TrimSpace(finding.Host),
		Share:               strings.TrimSpace(finding.Share),
		PrimaryPath:         strings.TrimSpace(finding.FilePath),
		ExploitabilityScore: score,
		PriorityTier:        exploitabilityTier(score),
		Completeness:        base.Completeness,
		ArchiveDerived:      strings.TrimSpace(finding.ArchivePath) != "",
		RelatedArtifacts:    extractRelatedArtifacts(finding),
	}
	if summary.ArchiveDerived {
		summary.BaseType = summary.Type
		summary.Type = "archive-derived-credential-cluster"
		summary.Label = "Archive-derived credential cluster"
		if summary.AccessHint == "" {
			summary.AccessHint = "contained within an inspected archive and may enable offline credential or access-material recovery"
		}
	}
	return summary, true
}

type accessPathClass struct {
	Type         string
	BaseType     string
	Label        string
	Why          string
	AccessHint   string
	Completeness string
	Score        int
}

func accessPathClassification(ruleID string, finding scanner.Finding) accessPathClass {
	switch ruleID {
	case adCorrelationRuleID:
		return accessPathClass{
			Type:         "ad-compromise-path",
			Label:        "AD compromise path",
			Why:          "NTDS and SYSTEM together strongly indicate offline domain credential extraction exposure.",
			AccessHint:   "offline extraction of domain credential material",
			Completeness: "complete",
			Score:        95,
		}
	case windowsCredCorrelationRuleID:
		match := strings.ToLower(strings.TrimSpace(finding.Match))
		completeness := "paired"
		score := 84
		if strings.Contains(match, "credentials") && strings.Contains(match, "vault") && strings.Contains(match, "protect") {
			completeness = "complete"
			score = 88
		}
		return accessPathClass{
			Type:         "windows-credential-store-exposure",
			Label:        "Windows credential-store exposure",
			Why:          "DPAPI Protect material with Windows credential-store artifacts can enable offline credential recovery workflows.",
			AccessHint:   "offline recovery of saved Windows credentials or web secrets",
			Completeness: completeness,
			Score:        score,
		}
	case privateKeyCorrelationRuleID:
		match := strings.ToLower(strings.TrimSpace(finding.Match))
		if strings.Contains(match, "client-auth") {
			return accessPathClass{
				Type:         "vpn-client-auth-access-path",
				Label:        "VPN/client-auth access path",
				Why:          "Private key material plus nearby client-auth artifacts suggests a reusable remote-access bundle.",
				AccessHint:   "direct VPN or client-auth access with bundled key material",
				Completeness: "complete",
				Score:        86,
			}
		}
		return accessPathClass{
			Type:         "ssh-access-path",
			Label:        "SSH access path",
			Why:          "Private key material plus nearby SSH support artifacts suggests a likely reusable SSH access path.",
			AccessHint:   "direct SSH access with exposed private key material",
			Completeness: "paired",
			Score:        78,
		}
	case browserCredCorrelationRuleID:
		match := strings.ToLower(strings.TrimSpace(finding.Match))
		completeness := "paired"
		score := 72
		if strings.Contains(match, "firefox") {
			score = 76
		}
		return accessPathClass{
			Type:         "browser-credential-store-exposure",
			Label:        "Browser credential-store exposure",
			Why:          "Exact paired browser profile artifacts suggest offline credential or session extraction may be possible from the exposed profile.",
			AccessHint:   "offline extraction of saved browser credentials or session material",
			Completeness: completeness,
			Score:        score,
		}
	case sqliteCorrelationRuleID:
		context := strings.ToLower(strings.TrimSpace(finding.Context))
		if strings.Contains(context, ".env") || strings.Contains(context, "appsettings.json") || strings.Contains(context, "web.config") || strings.Contains(context, "docker-compose.yml") {
			return accessPathClass{
				Type:         "application-credential-path",
				Label:        "Application credential path",
				Why:          "SQLite credential evidence reinforced by nearby application config suggests a usable application access path.",
				AccessHint:   "application login or service access using reinforced local credential material",
				Completeness: "paired",
				Score:        80,
			}
		}
		return accessPathClass{
			Type:         "database-access-path",
			Label:        "Database access path",
			Why:          "SQLite credential evidence reinforced by nearby database or backup context suggests a usable database access path.",
			AccessHint:   "database or service access from recovered local credential material",
			Completeness: "paired",
			Score:        78,
		}
	case backupCorrelationRuleID:
		match := strings.ToLower(strings.TrimSpace(finding.Match))
		complete := strings.Contains(match, "ntds") && strings.Contains(match, "system")
		completeness := "paired"
		score := 88
		if complete {
			completeness = "complete"
			score = 92
		} else if countArtifactFamilies(match) >= 3 {
			completeness = "multi-artifact"
			score = 90
		}
		return accessPathClass{
			Type:         "backup-exposure-path",
			Label:        "System-state backup exposure",
			Why:          "Grouped system-state backup artifacts suggest offline credential extraction or system-state recovery exposure.",
			AccessHint:   "offline extraction from copied hives or AD backup material",
			Completeness: completeness,
			Score:        score,
		}
	default:
		return accessPathClass{}
	}
}

func completenessBonus(completeness string) int {
	switch strings.ToLower(strings.TrimSpace(completeness)) {
	case "complete":
		return 4
	case "multi-artifact":
		return 6
	case "paired":
		return 2
	default:
		return 0
	}
}

func archiveBonus(finding scanner.Finding) int {
	if strings.TrimSpace(finding.ArchivePath) == "" {
		return 0
	}
	return 2
}

func exploitabilityTier(score int) string {
	switch {
	case score >= 90:
		return "high"
	case score >= 75:
		return "medium"
	default:
		return "low"
	}
}

func countArtifactFamilies(match string) int {
	count := 0
	for _, token := range []string{"ntds", "system", "sam", "security"} {
		if strings.Contains(match, token) {
			count++
		}
	}
	return count
}

func extractRelatedArtifacts(f scanner.Finding) []string {
	lines := strings.Split(strings.TrimSpace(f.Context), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(strings.ToLower(line), "paired ") || strings.Contains(strings.ToLower(line), "context:") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 && strings.TrimSpace(f.FilePath) != "" {
		out = append(out, f.FilePath)
	}
	return uniqueStrings(out)
}

func accessPathSummaryLabel(summary accessPathSummary) string {
	return firstNonEmpty(summary.Label, strings.ReplaceAll(summary.Type, "-", " "))
}

func accessPathPrimaryArtifact(summary accessPathSummary) string {
	return filepath.Base(strings.TrimSpace(summary.PrimaryPath))
}

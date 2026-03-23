package output

import (
	"path/filepath"
	"sort"
	"strings"

	"snablr/internal/scanner"
)

const adCorrelationRuleID = "correlation.ad.ntds_system"

func augmentFindingsForReporting(findings []scanner.Finding) []scanner.Finding {
	if len(findings) == 0 {
		return nil
	}

	out := cloneFindings(findings)
	existing := make(map[string]struct{}, len(out))
	for _, finding := range out {
		existing[correlationFindingKey(finding)] = struct{}{}
	}

	synthetic := buildADCorrelatedFindings(out)
	synthetic = append(synthetic, buildPrivateKeyCorrelatedFindings(out)...)
	synthetic = append(synthetic, buildBrowserCredentialStoreCorrelatedFindings(out)...)
	synthetic = append(synthetic, buildWindowsCredentialStoreCorrelatedFindings(out)...)
	synthetic = append(synthetic, buildBackupCorrelatedFindings(out)...)
	synthetic = append(synthetic, buildSQLiteCorrelatedFindings(out)...)
	for _, finding := range synthetic {
		key := correlationFindingKey(finding)
		if _, ok := existing[key]; ok {
			continue
		}
		existing[key] = struct{}{}
		out = append(out, finding)
	}

	sort.Slice(out, func(i, j int) bool {
		left := severityRank(out[i].Severity)
		right := severityRank(out[j].Severity)
		if left == right {
			if out[i].Host == out[j].Host {
				if out[i].Share == out[j].Share {
					return out[i].FilePath < out[j].FilePath
				}
				return out[i].Share < out[j].Share
			}
			return out[i].Host < out[j].Host
		}
		return left > right
	})
	return out
}

func buildADCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host  string
		share string
		dir   string
	}

	type pairBucket struct {
		ntds   []scanner.Finding
		system []scanner.Finding
	}

	grouped := make(map[bucketKey]*pairBucket)
	for _, finding := range findings {
		family := adArtifactFamily(finding)
		if family == "" {
			continue
		}
		key := bucketKey{
			host:  strings.ToLower(strings.TrimSpace(finding.Host)),
			share: strings.ToLower(strings.TrimSpace(finding.Share)),
			dir:   strings.ToLower(strings.TrimSpace(filepath.ToSlash(filepath.Dir(finding.FilePath)))),
		}
		if key.host == "" || key.share == "" || key.dir == "" {
			continue
		}
		bucket := grouped[key]
		if bucket == nil {
			bucket = &pairBucket{}
			grouped[key] = bucket
		}
		switch family {
		case "ntds":
			bucket.ntds = append(bucket.ntds, finding)
		case "system":
			bucket.system = append(bucket.system, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		if len(bucket.ntds) == 0 || len(bucket.system) == 0 {
			continue
		}
		out = append(out, newADCorrelatedFinding(selectBestCorrelationAnchor(bucket.ntds), selectBestCorrelationAnchor(bucket.system)))
	}
	return out
}

func adArtifactFamily(f scanner.Finding) string {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(f.FilePath)))
	switch base {
	case "ntds.dit", "ntds.dit.bak", "ntds.dit.old":
		return "ntds"
	case "system", "system.bak", "system.old":
		return "system"
	default:
		return ""
	}
}

func selectBestCorrelationAnchor(findings []scanner.Finding) scanner.Finding {
	best := findings[0]
	for _, finding := range findings[1:] {
		if finding.ConfidenceScore > best.ConfidenceScore {
			best = finding
			continue
		}
		if severityRank(finding.Severity) > severityRank(best.Severity) {
			best = finding
			continue
		}
		if finding.FilePath < best.FilePath {
			best = finding
		}
	}
	return best
}

func newADCorrelatedFinding(ntds, system scanner.Finding) scanner.Finding {
	ruleIDs := append([]string{}, ntds.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, system.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, adCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"NTDS.DIT and SYSTEM artifacts were found together in the same directory context",
		"paired AD database and SYSTEM hive artifacts enable offline credential extraction review",
	})

	signals := []scanner.SupportingSignal{
		{
			SignalType: "filename",
			RuleID:     ntds.RuleID,
			RuleName:   ntds.RuleName,
			Match:      filepath.Base(ntds.FilePath),
			Confidence: ntds.Confidence,
			Weight:     18,
			Reason:     "exact AD database artifact was identified",
		},
		{
			SignalType: "filename",
			RuleID:     system.RuleID,
			RuleName:   system.RuleName,
			Match:      filepath.Base(system.FilePath),
			Confidence: system.Confidence,
			Weight:     18,
			Reason:     "exact SYSTEM hive artifact was identified",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "both artifacts were found in the same host/share/directory context",
		},
		{
			SignalType: "correlation",
			RuleID:     adCorrelationRuleID,
			RuleName:   "AD Compromise Path: NTDS + SYSTEM",
			Match:      "NTDS.DIT + SYSTEM",
			Confidence: "high",
			Weight:     34,
			Reason:     "paired AD database and SYSTEM hive artifacts strongly indicate offline credential extraction exposure",
		},
	}

	tags := uniqueStrings(append(append([]string{}, ntds.Tags...), system.Tags...))
	tags = append(tags, "correlation:ad-compromise-path", "artifact:ntds", "artifact:system")
	sort.Strings(tags)

	context := "Paired artifact context:\n" + ntds.FilePath + "\n" + system.FilePath
	return scanner.Finding{
		RuleID:            adCorrelationRuleID,
		RuleName:          "AD Compromise Path: NTDS + SYSTEM",
		Severity:          "critical",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   82,
		ConfidenceReasons: reasons,
		Category:          "active-directory",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   82,
			FinalScore:                  82,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 36,
			ValueQualityScore:           0,
			ValueQualityLabel:           "low",
			ValueQualityReason:          "confidence comes from exact artifact identity and cross-file compromise-path correlation",
			CorrelationContribution:     34,
			PathContextContribution:     12,
		},
		Priority:            maxInt(ntds.Priority, system.Priority),
		PriorityReason:      firstNonEmpty(ntds.PriorityReason, system.PriorityReason),
		SharePriority:       maxInt(ntds.SharePriority, system.SharePriority),
		SharePriorityReason: firstNonEmpty(ntds.SharePriorityReason, system.SharePriorityReason),
		FilePath:            ntds.FilePath,
		Share:               ntds.Share,
		ShareDescription:    ntds.ShareDescription,
		ShareType:           ntds.ShareType,
		Host:                ntds.Host,
		Source:              firstNonEmpty(ntds.Source, system.Source),
		DFSNamespacePath:    firstNonEmpty(ntds.DFSNamespacePath, system.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(ntds.DFSLinkPath, system.DFSLinkPath),
		SignalType:          "correlation",
		Match:               "NTDS.DIT + SYSTEM",
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             "NTDS.DIT + SYSTEM in shared directory context",
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified NTDS.DIT and SYSTEM together in the same directory context, indicating a likely AD credential extraction path.",
		RuleExplanation:     "This finding is promoted only when exact NTDS.DIT and SYSTEM artifacts co-occur in the same host/share/directory context.",
		RuleRemediation:     "Restrict access immediately, remove unnecessary copies, and rotate affected credentials because paired AD database and SYSTEM hive artifacts can enable offline extraction workflows.",
		FromSYSVOL:          ntds.FromSYSVOL || system.FromSYSVOL,
		FromNETLOGON:        ntds.FromNETLOGON || system.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "filename", "path"},
		SupportingSignals:   signals,
		Tags:                tags,
	}
}

func correlationFindingKey(f scanner.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Host)) + "::" +
		strings.ToLower(strings.TrimSpace(f.Share)) + "::" +
		strings.ToLower(strings.TrimSpace(f.FilePath)) + "::" +
		strings.ToLower(strings.TrimSpace(f.RuleID))
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func adjustedSummarySnapshot(summary summarySnapshot, rawFindings, augmentedFindings []scanner.Finding) summarySnapshot {
	delta := len(augmentedFindings) - len(rawFindings)
	if delta > 0 {
		summary.MatchesFound += delta
	}
	return summary
}

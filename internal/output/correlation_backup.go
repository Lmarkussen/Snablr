package output

import (
	"path/filepath"
	"sort"
	"strings"

	"snablr/internal/backupinspect"
	"snablr/internal/scanner"
)

const backupCorrelationRuleID = "correlation.backup.system_state_exposure"

func buildBackupCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host    string
		share   string
		context string
	}

	type bucket struct {
		pathFamilies map[string][]scanner.Finding
		artifacts    map[string][]scanner.Finding
	}

	grouped := make(map[bucketKey]*bucket)
	for _, finding := range findings {
		context := backupinspect.BackupContext(finding.FilePath)
		if context == "" {
			continue
		}
		key := bucketKey{
			host:    strings.ToLower(strings.TrimSpace(finding.Host)),
			share:   strings.ToLower(strings.TrimSpace(finding.Share)),
			context: context,
		}
		item := grouped[key]
		if item == nil {
			item = &bucket{
				pathFamilies: make(map[string][]scanner.Finding),
				artifacts:    make(map[string][]scanner.Finding),
			}
			grouped[key] = item
		}
		if family := backupPathFamily(finding); family != "" {
			item.pathFamilies[family] = append(item.pathFamilies[family], finding)
		}
		if artifact := backupSecretArtifactFamily(finding); artifact != "" {
			item.artifacts[artifact] = append(item.artifacts[artifact], finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, item := range grouped {
		if len(item.artifacts) < 2 {
			continue
		}
		primary := selectBestBackupPrimary(item.artifacts)
		support := selectBestBackupSupport(item.artifacts, primary)
		pathSupport := selectBestBackupPathSupport(item.pathFamilies)
		out = append(out, newBackupCorrelatedFinding(primary, support, pathSupport, describeBackupArtifactSet(item.artifacts, item.pathFamilies)))
	}
	return out
}

func backupPathFamily(f scanner.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "backupinspect.path.windowsimagebackup":
		return "windowsimagebackup"
	case "backupinspect.path.system_volume_information":
		return "system-volume-information"
	case "backupinspect.path.regback":
		return "regback"
	case "backupinspect.path.windows_repair":
		return "windows-repair"
	default:
		return ""
	}
}

func backupSecretArtifactFamily(f scanner.Finding) string {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "backupinspect.path.windowsimagebackup",
		"backupinspect.path.system_volume_information",
		"backupinspect.path.regback",
		"backupinspect.path.windows_repair":
		return ""
	}
	base := strings.ToLower(strings.TrimSpace(filepath.Base(f.FilePath)))
	switch base {
	case "ntds.dit", "ntds.dit.bak", "ntds.dit.old":
		return "ntds"
	case "sam", "sam.bak", "sam.old":
		return "sam"
	case "system", "system.bak", "system.old":
		return "system"
	case "security", "security.bak", "security.old":
		return "security"
	default:
		return ""
	}
}

func selectBestBackupPrimary(artifacts map[string][]scanner.Finding) scanner.Finding {
	priority := []string{"ntds", "system", "sam", "security"}
	candidates := make([]scanner.Finding, 0, len(priority))
	for _, name := range priority {
		if findings := artifacts[name]; len(findings) > 0 {
			candidates = append(candidates, selectBestCorrelationAnchor(findings))
		}
	}
	return selectBestCorrelationAnchor(candidates)
}

func selectBestBackupSupport(artifacts map[string][]scanner.Finding, primary scanner.Finding) scanner.Finding {
	candidates := make([]scanner.Finding, 0)
	for _, findings := range artifacts {
		for _, finding := range findings {
			if finding.FilePath == primary.FilePath && finding.RuleID == primary.RuleID {
				continue
			}
			candidates = append(candidates, finding)
		}
	}
	return selectBestCorrelationAnchor(candidates)
}

func selectBestBackupPathSupport(pathFamilies map[string][]scanner.Finding) scanner.Finding {
	candidates := make([]scanner.Finding, 0)
	for _, findings := range pathFamilies {
		candidates = append(candidates, findings...)
	}
	if len(candidates) == 0 {
		return scanner.Finding{}
	}
	return selectBestCorrelationAnchor(candidates)
}

func describeBackupArtifactSet(artifacts map[string][]scanner.Finding, pathFamilies map[string][]scanner.Finding) string {
	parts := make([]string, 0, len(artifacts)+1)
	for _, artifact := range []string{"ntds", "sam", "system", "security"} {
		if len(artifacts[artifact]) > 0 {
			parts = append(parts, strings.ToUpper(artifact))
		}
	}
	if len(pathFamilies) > 0 {
		for _, name := range []string{"windowsimagebackup", "system-volume-information", "regback", "windows-repair"} {
			if len(pathFamilies[name]) > 0 {
				switch name {
				case "windowsimagebackup":
					parts = append(parts, "WindowsImageBackup")
				case "system-volume-information":
					parts = append(parts, "System Volume Information")
				case "regback":
					parts = append(parts, "RegBack")
				case "windows-repair":
					parts = append(parts, "Windows repair")
				}
				break
			}
		}
	}
	return strings.Join(parts, " + ")
}

func newBackupCorrelatedFinding(primary, support, pathSupport scanner.Finding, match string) scanner.Finding {
	ruleIDs := append([]string{}, primary.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, support.MatchedRuleIDs...)
	if pathSupport.RuleID != "" {
		ruleIDs = append(ruleIDs, pathSupport.MatchedRuleIDs...)
	}
	ruleIDs = append(ruleIDs, backupCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"multiple high-value system-state artifacts were found together in the same backup or copied system context",
		"paired hive or directory-service artifacts in backup storage can support offline credential extraction workflows",
	})

	contextLines := []string{primary.FilePath, support.FilePath}
	if pathSupport.FilePath != "" && pathSupport.FilePath != primary.FilePath && pathSupport.FilePath != support.FilePath {
		contextLines = append(contextLines, pathSupport.FilePath)
	}
	context := "Paired backup context:\n" + strings.Join(contextLines, "\n")

	signals := []scanner.SupportingSignal{
		{
			SignalType: primary.SignalType,
			RuleID:     primary.RuleID,
			RuleName:   primary.RuleName,
			Match:      filepath.Base(primary.FilePath),
			Confidence: primary.Confidence,
			Weight:     18,
			Reason:     "exact secret-store artifact was identified inside a backup or copied system-state context",
		},
		{
			SignalType: support.SignalType,
			RuleID:     support.RuleID,
			RuleName:   support.RuleName,
			Match:      filepath.Base(support.FilePath),
			Confidence: support.Confidence,
			Weight:     18,
			Reason:     "a second credential-relevant system artifact was found in the same backup context",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "artifacts were found under the same exact backup or copied system-state family",
		},
		{
			SignalType: "correlation",
			RuleID:     backupCorrelationRuleID,
			RuleName:   "System-State Backup Exposure Path",
			Match:      match,
			Confidence: "high",
			Weight:     34,
			Reason:     "multiple high-value system-state artifacts co-occurred in the same backup context",
		},
	}
	if pathSupport.RuleID != "" {
		signals = append(signals, scanner.SupportingSignal{
			SignalType: pathSupport.SignalType,
			RuleID:     pathSupport.RuleID,
			RuleName:   pathSupport.RuleName,
			Match:      pathSupport.Match,
			Confidence: pathSupport.Confidence,
			Weight:     10,
			Reason:     "the surrounding path is an exact Windows backup or restore storage family",
		})
	}

	tags := uniqueStrings(append(append(append([]string{}, primary.Tags...), support.Tags...), []string{
		"correlation:system-backup-exposure",
		"artifact:backup-family",
		"artifact:secret-store-backup",
	}...))
	sort.Strings(tags)

	score := 82
	if pathSupport.RuleID != "" {
		score = 86
	}

	return scanner.Finding{
		RuleID:            backupCorrelationRuleID,
		RuleName:          "System-State Backup Exposure Path",
		Severity:          "critical",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   score,
		ConfidenceReasons: reasons,
		Category:          "backup-exposure",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   score,
			FinalScore:                  score,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 36,
			ValueQualityScore:           0,
			ValueQualityLabel:           "medium",
			ValueQualityReason:          "confidence comes from exact artifact identity and grouped backup-context exposure rather than extracted values",
			CorrelationContribution:     34,
			PathContextContribution:     12,
		},
		Priority:            maxInt(primary.Priority, support.Priority),
		PriorityReason:      firstNonEmpty(primary.PriorityReason, support.PriorityReason),
		SharePriority:       maxInt(primary.SharePriority, support.SharePriority),
		SharePriorityReason: firstNonEmpty(primary.SharePriorityReason, support.SharePriorityReason),
		FilePath:            primary.FilePath,
		Share:               primary.Share,
		ShareDescription:    primary.ShareDescription,
		ShareType:           primary.ShareType,
		Host:                primary.Host,
		Source:              firstNonEmpty(primary.Source, support.Source, pathSupport.Source),
		ArchivePath:         firstNonEmpty(primary.ArchivePath, support.ArchivePath, pathSupport.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(primary.ArchiveMemberPath, support.ArchiveMemberPath, pathSupport.ArchiveMemberPath),
		ArchiveLocalInspect: primary.ArchiveLocalInspect || support.ArchiveLocalInspect || pathSupport.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(primary.DFSNamespacePath, support.DFSNamespacePath, pathSupport.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(primary.DFSLinkPath, support.DFSLinkPath, pathSupport.DFSLinkPath),
		SignalType:          "correlation",
		Match:               match,
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             match,
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified multiple high-value system-state artifacts in the same backup or copied system context.",
		RuleExplanation:     "This finding is promoted only when multiple exact secret-store artifacts co-occur under the same Windows backup, restore, or copied system-state path family.",
		RuleRemediation:     "Restrict access immediately, remove unnecessary system-state backups from shared storage, and rotate affected credentials because grouped hive or directory-service artifacts can enable offline extraction workflows.",
		FromSYSVOL:          primary.FromSYSVOL || support.FromSYSVOL || pathSupport.FromSYSVOL,
		FromNETLOGON:        primary.FromNETLOGON || support.FromNETLOGON || pathSupport.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "path", "filename"},
		SupportingSignals:   signals,
		Tags:                tags,
	}
}

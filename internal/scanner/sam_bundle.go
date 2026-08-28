package scanner

import (
	"fmt"
	"strings"

	"snablr/internal/artifactbundle"
	"snablr/internal/rules"
)

const samBundleFindingRuleID = "windows.sam.bundle_parsed"

func findingFromSAMBundle(meta FileMetadata, result *artifactbundle.SAMBundleResult) Finding {
	origin := result.Origin
	filePath := meta.FilePath
	archivePath := ""
	memberPath := ""
	if strings.EqualFold(origin.SourceType, "wim") && origin.ContainerPath != "" {
		archivePath = origin.ContainerPath
		memberPath = origin.SYSTEMPath
		filePath = origin.ContainerPath + "!" + origin.SYSTEMPath
	} else if origin.SYSTEMPath != "" {
		filePath = origin.SYSTEMPath
	}
	accountText := fmt.Sprintf("SAM + SYSTEM parsed successfully; accounts recovered: %d; NT hashes recovered: %d", result.AccountCount, result.RecoveredHashCount)
	if len(result.AccountErrors) > 0 {
		accountText += fmt.Sprintf("; account records with errors: %d", len(result.AccountErrors))
	}
	finding := Finding{
		RuleID:              samBundleFindingRuleID,
		RuleName:            "Windows SAM + SYSTEM parsed",
		Severity:            string(rules.SeverityCritical),
		Confidence:          string(rules.ConfidenceHigh),
		RuleConfidence:      string(rules.ConfidenceHigh),
		ConfidenceScore:     100,
		ConfidenceReasons:   []string{"valid SYSTEM boot-key derivation and SAM account parsing succeeded"},
		Category:            "windows-credentials",
		TriageClass:         triageActionable,
		Actionable:          true,
		FilePath:            filePath,
		Share:               firstNonEmptyValue(origin.Share, meta.Share),
		ShareDescription:    meta.ShareDescription,
		ShareType:           meta.ShareType,
		Host:                firstNonEmptyValue(origin.Host, meta.Host),
		Source:              firstNonEmptyValue(meta.Source, origin.SourceType),
		ArchivePath:         archivePath,
		ArchiveMemberPath:   memberPath,
		ArchiveLocalInspect: archivePath != "",
		SignalType:          "validated",
		Match:               "validated SAM + SYSTEM local-account database",
		MatchedText:         accountText,
		MatchedTextRedacted: accountText,
		Snippet:             accountText,
		Context:             accountText,
		ContextRedacted:     accountText,
		RuleExplanation:     "A SYSTEM hive boot key and SAM domain key were successfully validated, allowing structured local-account recovery.",
		RuleRemediation:     "Remove exposed SAM and SYSTEM copies from shared storage, restrict access to backup artifacts, and rotate affected local credentials.",
		MatchedRuleIDs:      []string{samBundleFindingRuleID},
		MatchedSignalTypes:  []string{"validated"},
		SupportingSignals: []SupportingSignal{{
			SignalType: "validated",
			RuleID:     samBundleFindingRuleID,
			RuleName:   "Windows SAM + SYSTEM parsed",
			Match:      "SAM + SYSTEM successfully parsed",
			Confidence: "high",
			Weight:     baseSignalWeight("validated"),
			Reason:     "SYSTEM boot-key derivation and SAM account parsing produced structured local-account evidence",
		}},
		Tags: []string{"artifact:windows-sam", "validated:sam-system", "credential-recovery:nt-hash-count-only"},
	}
	return applyTriageMetadata(finding)
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

package scanner

import (
	"fmt"
	"strings"

	"snablr/internal/artifactbundle"
	"snablr/internal/rules"
)

const ntdsBundleFindingRuleID = "windows.ntds.bundle_parsed"

func findingFromNTDSBundle(meta FileMetadata, result *artifactbundle.NTDSBundleResult) Finding {
	origin := result.Origin
	filePath := meta.FilePath
	archivePath := ""
	memberPath := ""
	if strings.EqualFold(origin.SourceType, "wim") && origin.ContainerPath != "" {
		archivePath = origin.ContainerPath
		memberPath = origin.NTDSPath
		filePath = origin.ContainerPath + "!" + origin.NTDSPath
	} else if origin.NTDSPath != "" {
		filePath = origin.NTDSPath
	}
	text := fmt.Sprintf("NTDS.DIT + SYSTEM parsed successfully; domain accounts recovered: %d; current NT hashes recovered: %d", result.AccountsDiscovered, result.AccountsWithCurrentNTHash)
	return applyTriageMetadata(Finding{
		RuleID: ntdsBundleFindingRuleID, RuleName: "Windows NTDS.DIT + SYSTEM parsed",
		Severity: string(rules.SeverityCritical), Confidence: string(rules.ConfidenceHigh), RuleConfidence: string(rules.ConfidenceHigh), ConfidenceScore: 100,
		ConfidenceReasons: []string{"valid SYSTEM boot-key derivation, NTDS PEK recovery, and current NT credential decoding succeeded"},
		Category:          "windows-credentials", TriageClass: triageActionable, Actionable: true,
		FilePath: filePath, Share: firstNonEmptyValue(origin.Share, meta.Share), ShareDescription: meta.ShareDescription, ShareType: meta.ShareType,
		Host: firstNonEmptyValue(origin.Host, meta.Host), Source: firstNonEmptyValue(meta.Source, origin.SourceType), ArchivePath: archivePath, ArchiveMemberPath: memberPath, ArchiveLocalInspect: archivePath != "",
		SignalType: "validated", Match: "validated NTDS.DIT + SYSTEM current NT credential material", MatchedText: text, MatchedTextRedacted: text, Snippet: text, Context: text, ContextRedacted: text,
		RuleExplanation: "A paired SYSTEM boot key and NTDS PEK were successfully validated, allowing current domain NT credential metadata recovery without exposing hash bytes.",
		RuleRemediation: "Remove exposed NTDS.DIT and SYSTEM copies from shared storage, restrict access to domain database backups, and rotate affected domain credentials.",
		MatchedRuleIDs:  []string{ntdsBundleFindingRuleID}, MatchedSignalTypes: []string{"validated"},
		SupportingSignals: []SupportingSignal{{SignalType: "validated", RuleID: ntdsBundleFindingRuleID, RuleName: "Windows NTDS.DIT + SYSTEM parsed", Match: "NTDS.DIT + SYSTEM successfully parsed", Confidence: "high", Weight: baseSignalWeight("validated"), Reason: "NTDS PEK recovery and current NT credential decoding produced structured domain-account evidence"}},
		Tags:              []string{"artifact:windows-ntds", "validated:ntds-system", "credential-recovery:nt-hash-count-only"},
	})
}

func (e *Engine) exportNTDSBundle(result *artifactbundle.NTDSBundleResult) {
	if e == nil || e.credentialExporter == nil || result == nil {
		return
	}
	source := result.Origin.NTDSPath
	if strings.EqualFold(result.Origin.SourceType, "wim") && result.Origin.ContainerPath != "" {
		source = result.Origin.ContainerPath + "!" + result.Origin.NTDSPath
	}
	for _, account := range result.Accounts {
		hash := account.CurrentNTHashForExport()
		if len(hash) == 0 {
			continue
		}
		domain := account.Domain
		if domain == "" {
			domain = result.Domain
		}
		if err := e.credentialExporter.ExportNTDSCurrentHash(domain, account.SamAccountName, source, account.RID, account.SID, account.Machine, account.Disabled, hash); err != nil && e.log != nil {
			e.log.Errorf("NTDS credential export failed for account %s: %v", account.SamAccountName, err)
		}
	}
}

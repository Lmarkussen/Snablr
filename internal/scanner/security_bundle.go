package scanner

import (
	"fmt"
	"strings"

	"snablr/internal/artifactbundle"
	"snablr/internal/rules"
)

const securityBundleFindingRuleID = "windows.security.bundle_parsed"

func findingFromSecurityBundle(meta FileMetadata, result *artifactbundle.SecurityBundleResult) Finding {
	origin := result.Origin
	filePath := meta.FilePath
	archivePath := ""
	memberPath := ""
	if strings.EqualFold(origin.SourceType, "wim") && origin.ContainerPath != "" {
		archivePath = origin.ContainerPath
		memberPath = origin.SECURITYPath
		filePath = origin.ContainerPath + "!" + origin.SECURITYPath
	} else if origin.SECURITYPath != "" {
		filePath = origin.SECURITYPath
	}
	text := fmt.Sprintf("SECURITY + SYSTEM parsed successfully; LSA secrets decoded: %d; cached domain entries decoded: %d", result.SecretsDecoded, result.CachedDomainDecoded)
	return applyTriageMetadata(Finding{
		RuleID:              securityBundleFindingRuleID,
		RuleName:            "Windows SECURITY + SYSTEM parsed",
		Severity:            string(rules.SeverityHigh),
		Confidence:          string(rules.ConfidenceHigh),
		RuleConfidence:      string(rules.ConfidenceHigh),
		ConfidenceScore:     100,
		ConfidenceReasons:   []string{"valid SYSTEM boot-key derivation and SECURITY LSA decoding succeeded"},
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
		Match:               "validated SECURITY + SYSTEM LSA material",
		MatchedText:         text,
		MatchedTextRedacted: text,
		Snippet:             text,
		Context:             text,
		ContextRedacted:     text,
		RuleExplanation:     "A SYSTEM boot key and modern SECURITY LSA protection data were successfully validated, allowing structured metadata recovery without exposing secret bytes.",
		RuleRemediation:     "Remove exposed SECURITY and SYSTEM copies from shared storage, restrict access to backup artifacts, and rotate affected machine, service, and cached-domain credentials as appropriate.",
		MatchedRuleIDs:      []string{securityBundleFindingRuleID},
		MatchedSignalTypes:  []string{"validated"},
		SupportingSignals: []SupportingSignal{{
			SignalType: "validated", RuleID: securityBundleFindingRuleID,
			RuleName: "Windows SECURITY + SYSTEM parsed", Match: "SECURITY + SYSTEM successfully parsed",
			Confidence: "high", Weight: baseSignalWeight("validated"),
			Reason: "SYSTEM boot-key derivation and SECURITY LSA decoding produced structured credential-risk metadata",
		}},
		Tags: []string{"artifact:windows-security", "validated:security-system", "credential-recovery:metadata-only"},
	})
}

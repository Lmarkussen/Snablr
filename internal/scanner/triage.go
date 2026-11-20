package scanner

import (
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/keyinspect"
)

const (
	triageActionable = "actionable"
	triageConfigOnly = "config-only"
	triageWeakReview = "weak-review"
)

func applyTriageMetadata(f Finding) Finding {
	f.Correlated = len(f.MatchedSignalTypes) > 1 || len(f.MatchedRuleIDs) > 1
	f.TriageClass = triageClassForFinding(f)
	f.Actionable = f.TriageClass == triageActionable

	switch f.TriageClass {
	case triageConfigOnly:
		if severityRank(f.Severity) > severityRank("low") {
			f.Severity = "low"
		}
		if f.ConfidenceScore > 24 {
			f.ConfidenceScore = 24
		}
		f.Confidence = "low"
		f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "configuration artifact was identified without actionable evidence")
	case triageWeakReview:
		if severityRank(f.Severity) > severityRank("medium") {
			f.Severity = "medium"
		}
		if f.ConfidenceScore > 34 {
			f.ConfidenceScore = 34
		}
		if strings.TrimSpace(f.Confidence) == "" || confidenceRank(f.Confidence) > confidenceRank("medium") {
			f.Confidence = "medium"
		}
		f.ConfidenceReasons = appendUniqueReason(f.ConfidenceReasons, "heuristic review signal did not include actionable evidence")
	default:
		if strings.TrimSpace(f.Confidence) == "" && f.ConfidenceScore > 0 {
			f.Confidence = confidenceLevelForScore(f.ConfidenceScore)
		}
	}

	return f
}

func triageClassForFinding(f Finding) string {
	if isConfigOnlyFinding(f) {
		return triageConfigOnly
	}
	if isWeakReviewFinding(f) {
		return triageWeakReview
	}
	return triageActionable
}

func isConfigOnlyFinding(f Finding) bool {
	if !strings.EqualFold(strings.TrimSpace(f.Category), "configuration") {
		return false
	}
	return !hasStrongEvidence(f)
}

func isWeakReviewFinding(f Finding) bool {
	for _, tag := range f.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "sccm:synthetic-contract") {
			return true
		}
	}
	return !hasStrongEvidence(f)
}

func hasStrongEvidence(f Finding) bool {
	if needsDecryptionFirst(f) {
		return false
	}
	// Installed third-party library code holds documentation examples and
	// test fixtures; only name-identified direct-exploit artifacts (a dump or
	// a hive copied there) stay actionable.
	if credentialanalysis.ThirdPartyLibraryPath(f.FilePath) && !isDirectExploitArtifact(f) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(findingPrimarySignal(f)), "correlation") {
		return true
	}

	if hasUsablePrimaryEvidence(f) {
		return true
	}

	return isDirectExploitArtifact(f)
}

func hasUsablePrimaryEvidence(f Finding) bool {
	quality := assessFindingValueQuality(f)
	if quality.Weak {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(findingPrimarySignal(f))) {
	case "content":
		return true
	case "validated":
		return !isValidatedArtifactIdentityOnly(f)
	default:
		return false
	}
}

func isDirectExploitArtifact(f Finding) bool {
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "filename.private_key_artifacts",
		"filename.secret_store_artifacts",
		"filename.windows_hive_artifacts",
		"filename.ad_database_backup_artifacts",
		"filename.windows_hive_backup_artifacts",
		"filename.kerberos_ticket_artifacts",
		"filename.memory_dump_artifacts",
		"extension.virtual_disk_and_memory_images":
		return true
	default:
		return false
	}
}

// needsDecryptionFirst reports findings whose evidence is protected secret
// material: it must be decrypted or cracked before it can be used, and
// Snablr does neither, so it is review material rather than actionable.
// The same holds for credentials the harvester could not confirm.
func needsDecryptionFirst(f Finding) bool {
	// The key inspector tags a passphrase-protected key; correlation carries
	// the tag to the file's finding whichever rule ends up primary (the
	// id_rsa filename rule or a header content rule).
	if findingHasTag(f, keyinspect.EncryptedKeyTag) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case ReviewCredentialRuleID, "content.sccm_naa_policy_secret":
		return true
	case "content.remote_access_saved_password":
		// RDP connection files and RDCMan <password> elements store the
		// saved password as a DPAPI blob bound to the user who saved it
		// (hex in .rdp, base64 "AQAAANCMnd8BFdERjHoAwE/Cl+s" in RDCMan).
		match := strings.TrimSpace(f.Match)
		return strings.HasPrefix(strings.ToLower(match), "password 51:b:") ||
			strings.HasPrefix(match, "<password>AQAAANCMnd8BFdERjHoAwE/Cl+s")
	default:
		return false
	}
}

func findingHasTag(f Finding, tag string) bool {
	for _, value := range f.Tags {
		if strings.EqualFold(strings.TrimSpace(value), tag) {
			return true
		}
	}
	return false
}

func isValidatedArtifactIdentityOnly(f Finding) bool {
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
	switch {
	case strings.HasPrefix(ruleID, "backupinspect.path."):
		return true
	case strings.HasPrefix(ruleID, "browsercredinspect."):
		return true
	case strings.HasPrefix(ruleID, "dbinspect.artifact."):
		return true
	case strings.HasPrefix(ruleID, "dbinspect.infrastructure."):
		return true
	case strings.HasPrefix(ruleID, "wincredinspect.path."):
		return true
	case ruleID == "awsinspect.path.credentials":
		return true
	case ruleID == "awsinspect.path.config":
		return true
	case strings.HasPrefix(ruleID, "windowsinspect.gpp."):
		// A Group Policy Preferences document is actionable for a cpassword
		// that decrypts; group memberships and values that do not decrypt
		// are review material.
		return !gppCarriesConfirmedCredential(f)
	case ruleID == "windowsinspect.unattend.structured":
		// An unattend file is actionable for the credentials it carries;
		// templates and files Windows setup has scrubbed carry none.
		return !unattendCarriesCredential(f)
	default:
		return false
	}
}

func findingPrimarySignal(f Finding) string {
	if strings.TrimSpace(f.SignalType) != "" {
		return strings.TrimSpace(f.SignalType)
	}
	if len(f.MatchedSignalTypes) > 0 {
		return strings.TrimSpace(f.MatchedSignalTypes[0])
	}
	return ""
}

func appendUniqueReason(values []string, reason string) []string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return values
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), reason) {
			return values
		}
	}
	return append(values, reason)
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// unattendCarriesCredential reports whether an unattend document holds a
// credential value that is not a placeholder, scrubbed or template value.
func unattendCarriesCredential(f Finding) bool {
	return unattendTextCarriesCredential(f.FilePath, f.MatchedText)
}

func unattendTextCarriesCredential(path, text string) bool {
	return len(credentialanalysis.Harvest(credentialanalysis.HarvestInput{Content: []byte(text), Path: path})) > 0
}

// gppCarriesConfirmedCredential reports whether a Group Policy Preferences
// document holds a cpassword that decrypts to a credential.
func gppCarriesConfirmedCredential(f Finding) bool {
	for _, candidate := range credentialanalysis.Harvest(credentialanalysis.HarvestInput{Content: []byte(f.MatchedText), Path: f.FilePath}) {
		if candidate.Verification == credentialanalysis.Confirmed {
			return true
		}
	}
	return false
}

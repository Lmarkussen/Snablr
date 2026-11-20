package scanner

import (
	"fmt"
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
)

// ConfirmedCredentialRuleID identifies the finding raised when the credential
// harvester recovers confirmed credential material from a file.
const ConfirmedCredentialRuleID = "credentialanalysis.confirmed_credential"

var confirmedCredentialRule = rules.Rule{
	ID:          ConfirmedCredentialRuleID,
	Name:        "Confirmed Credential Material",
	Description: "The credential harvester recovered confirmed credential material from this file.",
	Type:        rules.RuleTypeContent,
	Severity:    rules.SeverityHigh,
	Confidence:  rules.ConfidenceHigh,
	Category:    "credentials",
	Tags:        []string{"credentials", "harvested", "confirmed"},
	Explanation: "The file contains credential material the harvester confirmed from its structure, such as an explicit account and password in the same record, a connection string with credentials, or a recognised hash record.",
	Remediation: "Remove the credential from the file, rotate it, and keep secrets in a dedicated secret store with restricted access.",
}

// ReviewCredentialRuleID identifies the review finding raised for a file
// whose harvested credential material could not be confirmed and that has no
// other finding.
const ReviewCredentialRuleID = "credentialanalysis.review_credential"

var reviewCredentialRule = rules.Rule{
	ID:          ReviewCredentialRuleID,
	Name:        "Credential Material For Review",
	Description: "The credential harvester recovered credential material from this file that it could not confirm.",
	Type:        rules.RuleTypeContent,
	Severity:    rules.SeverityMedium,
	Confidence:  rules.ConfidenceMedium,
	Category:    "credentials",
	Tags:        []string{"credentials", "harvested", "review"},
	Explanation: "The file contains credential-like material the harvester could not confirm, such as a password without an account, an encrypted or encoded value, or a value whose meaning depends on context. It needs manual review.",
	Remediation: "Review the material; if it is a live credential, remove it from the file, rotate it, and keep secrets in a dedicated secret store with restricted access.",
}

// minReviewCredentialValueLength drops trivially short values ("0", "33")
// that the harvester keeps as review candidates in Windows system files.
const minReviewCredentialValueLength = 4

// reviewCredentialFinding returns a review finding for harvested credential
// material that could not be confirmed, so it is visible and not only kept
// in the persisted credential evidence. Private keys are reported by the key
// inspector. The caller raises it only for files with no other finding.
func reviewCredentialFinding(meta FileMetadata, candidates []credentialanalysis.Candidate) (Finding, bool) {
	if strings.EqualFold(meta.Extension, ".mof") {
		// WMI class definitions name trace providers and properties after
		// passwords and secrets; they are noise on every Windows host.
		return Finding{}, false
	}
	review := make([]credentialanalysis.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Verification != credentialanalysis.Review || strings.EqualFold(candidate.CredentialType, "private_key") {
			continue
		}
		if len([]rune(strings.TrimSpace(candidate.Value))) < minReviewCredentialValueLength {
			continue
		}
		review = append(review, candidate)
	}
	if len(review) == 0 {
		return Finding{}, false
	}

	first := review[0]
	credentialType := strings.TrimSpace(first.CredentialType)
	if credentialType == "" {
		credentialType = "credential"
	}
	summary := "unconfirmed " + credentialType
	if first.Encrypted {
		summary = "encrypted " + credentialType
	}
	matched := first.Value
	if identity := strings.TrimSpace(first.Identity); identity != "" {
		summary += " for account " + identity
		matched = identity + " : " + first.Value
	}
	if extra := len(review) - 1; extra > 0 {
		summary += fmt.Sprintf(" (+%d more)", extra)
	}

	return newFinding(reviewCredentialRule, meta, findingEvidence{
		SignalType:          "content",
		Match:               summary,
		MatchedText:         matched,
		MatchedTextRedacted: redactSensitiveText(matched),
		PotentialAccount:    strings.TrimSpace(first.Identity),
	}), true
}

// findingsFromConfirmedCredentials raises one finding per file for confirmed
// harvested credential material, so a recovered credential is always visible
// as a finding and not only in the persisted credential evidence. Encrypted
// material is never presented as confirmed, and private keys are reported by
// the key inspector.
func findingsFromConfirmedCredentials(meta FileMetadata, candidates []credentialanalysis.Candidate) []Finding {
	confirmed := make([]credentialanalysis.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Verification != credentialanalysis.Confirmed || candidate.Encrypted || strings.TrimSpace(candidate.Value) == "" {
			continue
		}
		if strings.EqualFold(candidate.CredentialType, "private_key") {
			continue
		}
		confirmed = append(confirmed, candidate)
	}
	if len(confirmed) == 0 {
		return nil
	}

	first := confirmed[0]
	credentialType := strings.TrimSpace(first.CredentialType)
	if credentialType == "" {
		credentialType = "credential"
	}
	summary := "confirmed " + credentialType
	matched := first.Value
	if identity := strings.TrimSpace(first.Identity); identity != "" {
		summary += " for account " + identity
		matched = identity + " : " + first.Value
	}
	if extra := len(confirmed) - 1; extra > 0 {
		summary += fmt.Sprintf(" (+%d more)", extra)
	}

	return []Finding{newFinding(confirmedCredentialRule, meta, findingEvidence{
		SignalType:          "validated",
		Match:               summary,
		MatchedText:         matched,
		MatchedTextRedacted: redactSensitiveText(matched),
		PotentialAccount:    strings.TrimSpace(first.Identity),
	})}
}

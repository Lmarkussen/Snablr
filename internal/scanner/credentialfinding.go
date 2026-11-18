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

package output

import (
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func credentialCandidatesFromFindings(findings []scanner.Finding) []credentialanalysis.Candidate {
	var candidates []credentialanalysis.Candidate
	for _, finding := range findings {
		if isDirectInspectorCredentialFinding(finding.RuleID) {
			continue
		}
		// A path/artifact that merely *indicates* a credential store exists is
		// inventory and attack-surface evidence, never a recovered secret. It
		// must not enter the Credential & Secret Material analysis.
		if isCredentialStorePresenceFinding(finding.RuleID) {
			continue
		}
		if entry, ok := credentialEntryFromFinding(finding); ok {
			valueParts := make([]string, 0, len(entry.Fields))
			identity := ""
			for _, field := range entry.Fields {
				valueParts = append(valueParts, field.Label+"="+field.Value)
				if strings.EqualFold(field.Label, "User") {
					identity = field.Value
				}
			}
			credentialType := strings.ToLower(strings.ReplaceAll(entry.Group, " ", "_"))
			if strings.Contains(strings.ToLower(entry.Group), "private key") {
				credentialType = "private_key"
			}
			candidates = append(candidates, credentialanalysis.Candidate{
				Verification: credentialanalysis.Confirmed, CredentialType: credentialType,
				Identity: identity, Value: strings.Join(valueParts, "\x00"), Source: exportSourcePath(finding),
				Host: finding.Host, Share: finding.Share, Path: finding.FilePath,
				ValidationBasis: "structured_credential_material",
				Evidence:        []credentialanalysis.Evidence{{RuleID: finding.RuleID, Source: finding.Source, Path: finding.FilePath}},
			})
			continue
		}

		values := parseAssignmentValues(joinNonEmpty(finding.MatchedText, finding.Context))
		// Password aliases (including Norwegian) are resolved by the shared
		// semantic layer; non-password secret families keep their explicit
		// fallbacks so existing behavior is unchanged.
		passwordValue := credentialanalysis.SelectFieldValue(values, credentialanalysis.FieldRolePassword)
		password := firstNonEmpty(passwordValue, values["secret"], values["token"], values["api_key"])
		if password == "" {
			continue
		}
		// A syntactically valid assignment is not enough: the right-hand side
		// must have a scalar secret shape. This rejects SQL variables, function
		// calls, schema/metadata definitions and prose fragments that would
		// otherwise be exported as credentials.
		if _, reject := credentialanalysis.NonSecretValueShape(password); reject {
			continue
		}
		identity := credentialanalysis.SelectFieldValue(values, credentialanalysis.FieldRoleIdentity)
		if _, reject := credentialanalysis.NonSecretValueShape(identity); reject {
			identity = ""
		}
		verification := credentialanalysis.Review
		basis := "credential_like_value_without_conclusive_identity_association"
		reasons := []string{"credential-like value extracted but identity association could not be conclusively established"}
		if identity != "" && passwordValue != "" {
			verification = credentialanalysis.Confirmed
			basis = "structured_config_pair"
			reasons = nil
		}
		if looksPlaceholderCredential(password) {
			verification = credentialanalysis.Review
			basis = "placeholder_like_value_requires_review"
			reasons = append(reasons, "value resembles template or placeholder syntax")
		}
		credentialType := "password"
		if values["token"] != "" || values["api_key"] != "" {
			credentialType = "token"
		}
		candidates = append(candidates, credentialanalysis.Candidate{
			Verification: verification, CredentialType: credentialType, Identity: identity, Value: password,
			Source: exportSourcePath(finding), Host: finding.Host, Share: finding.Share, Path: finding.FilePath,
			ValidationBasis: basis, ReviewReasons: reasons,
			Evidence: []credentialanalysis.Evidence{{RuleID: finding.RuleID, Source: finding.Source, Path: finding.FilePath}},
		})
	}
	return candidates
}

func isDirectInspectorCredentialFinding(ruleID string) bool {
	switch ruleID {
	case "keyinspect.content.private_key_header",
		"dbinspect.access.connection_string",
		"dbinspect.access.dsn":
		return true
	default:
		return false
	}
}

// isCredentialStorePresenceFinding reports whether a rule identifies the
// presence of a credential store or artifact rather than a recovered value.
// Such findings stay visible as supporting/inventory evidence but are never
// projected into the credential material analysis.
func isCredentialStorePresenceFinding(ruleID string) bool {
	switch strings.ToLower(strings.TrimSpace(ruleID)) {
	case "wincredinspect.path.credentials",
		"wincredinspect.path.vault",
		"wincredinspect.path.protect",
		"browsercredinspect.firefox.logins",
		"browsercredinspect.firefox.key4",
		"browsercredinspect.chromium.login_data",
		"browsercredinspect.chromium.cookies",
		"correlation.windows.dpapi_credential_store",
		"correlation.browser.profile_credential_store",
		"awsinspect.path.credentials",
		"awsinspect.path.config":
		return true
	default:
		return false
	}
}

func analyzeCandidates(findings []scanner.Finding, candidates []credentialanalysis.Candidate) credentialanalysis.Report {
	all := append([]credentialanalysis.Candidate{}, credentialCandidatesFromFindings(findings)...)
	all = append(all, candidates...)
	return credentialanalysis.Analyze(all)
}

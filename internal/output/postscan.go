package output

import (
	"strings"

	"snablr/internal/credentialanalysis"
	"snablr/internal/scanner"
)

func credentialCandidatesFromFindings(findings []scanner.Finding) []credentialanalysis.Candidate {
	var candidates []credentialanalysis.Candidate
	for _, finding := range findings {
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
		password := firstNonEmpty(values["password"], values["passwd"], values["secret"], values["token"], values["api_key"])
		if password == "" {
			continue
		}
		identity := firstNonEmpty(values["username"], values["user"], values["login"], values["account"], values["email"])
		verification := credentialanalysis.Review
		basis := "credential_like_value_without_conclusive_identity_association"
		reasons := []string{"credential-like value extracted but identity association could not be conclusively established"}
		if identity != "" && (values["password"] != "" || values["passwd"] != "") {
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

func analyzeCandidates(findings []scanner.Finding, candidates []credentialanalysis.Candidate) credentialanalysis.Report {
	all := append([]credentialanalysis.Candidate{}, credentialCandidatesFromFindings(findings)...)
	all = append(all, candidates...)
	return credentialanalysis.Analyze(all)
}

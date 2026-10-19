package findings

import (
	"strings"

	"snablr/internal/credentialanalysis"
)

type pairingDecision struct {
	Status               string
	Basis                string
	Confirmed            bool
	OriginalVerification string
	Opaque               bool
}

func interpretCredential(candidate credentialanalysis.Candidate) pairingDecision {
	decision := pairingDecision{OriginalVerification: string(candidate.Verification)}
	if isOpaqueCredential(candidate) {
		decision.Status = "Encrypted / opaque material"
		decision.Basis = "persisted value is explicitly marked or formatted as opaque material"
		decision.Opaque = true
		return decision
	}
	if strings.TrimSpace(candidate.Value) == "" {
		decision.Status = "Password only / value unavailable"
		decision.Basis = "no persisted material value"
		return decision
	}
	if _, ok := deriveConnectionPair(candidate); ok {
		decision.Status = "Confirmed pair (Finder-derived)"
		decision.Basis = "explicit username and password fields in the same persisted connection string"
		decision.Confirmed = true
		return decision
	}
	if strings.TrimSpace(candidate.Identity) == "" {
		decision.Status = "Password only / identity not established"
		decision.Basis = "no persisted identity is associated with this observation"
		return decision
	}
	if !isUsernamePasswordType(candidate.CredentialType) {
		decision.Status = "Credential material / pairing not applicable"
		decision.Basis = "persisted material type is not a username/password record"
		return decision
	}
	if candidate.Verification == credentialanalysis.Confirmed {
		decision.Status = "Confirmed pair"
		decision.Basis = firstPairingBasis(candidate.ValidationBasis, "persisted credential record contains an explicit identity and value")
		decision.Confirmed = true
		return decision
	}
	if candidate.Verification == credentialanalysis.Review && hasPersistedPairObservation(candidate) {
		decision.Status = "Confirmed pair (Finder-derived)"
		decision.Basis = "persisted candidate contains an identity and value in the same observation"
		decision.Confirmed = true
		return decision
	}
	decision.Status = "Uncertain pairing"
	decision.Basis = "persisted verification did not establish a username/password pairing"
	return decision
}

func isUsernamePasswordType(credentialType string) bool {
	switch strings.ToLower(strings.TrimSpace(credentialType)) {
	case "password", "passwd", "pwd", "passord", "secret", "shared_secret":
		return true
	default:
		return false
	}
}

func hasPersistedPairObservation(candidate credentialanalysis.Candidate) bool {
	return len(candidate.Evidence) > 0 || strings.TrimSpace(candidate.Path) != ""
}

func isOpaqueCredential(candidate credentialanalysis.Candidate) bool {
	if candidate.Encrypted {
		return true
	}
	value := strings.ToLower(strings.TrimSpace(candidate.Value))
	for _, marker := range []string{"ciphertext", "encrypted", "opaque", "enc:", "enc[", "dpapi"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	basis := strings.ToLower(strings.TrimSpace(candidate.ValidationBasis))
	return strings.Contains(basis, "encrypted") || strings.Contains(basis, "opaque")
}

func firstPairingBasis(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

package credentialanalysis

import (
	"regexp"
	"strings"
)

// An ASP.NET <machineKey> with explicit keys signs (validationKey) and
// encrypts (decryptionKey) ViewState, forms authentication tickets and
// other protected data for every application that shares it. With the keys,
// a ViewState payload can be forged, which typically means code execution in
// the application pool. AutoGenerate values are generated per machine and
// are not in the file.

const machineKeyBasis = "ASP.NET machineKey with explicit keys"

var (
	machineValidationKeyPattern = regexp.MustCompile(`^[0-9A-Fa-f]{32,256}$`)
	machineDecryptionKeyPattern = regexp.MustCompile(`^[0-9A-Fa-f]{16,128}$`)
)

// harvestMachineKeyNode reports a <machineKey> element with an explicit
// validation key as one machine_key credential holding both keys and the
// algorithms needed to use them.
func harvestMachineKeyNode(node *xmlHarvestNode, add func(Candidate)) {
	if node == nil || !strings.EqualFold(node.name, "machinekey") {
		return
	}
	validationKey := strings.TrimSpace(node.attrs["validation_key"])
	if !machineValidationKeyPattern.MatchString(validationKey) {
		return
	}
	parts := []string{"validationKey=" + validationKey, "validation=" + firstNonEmpty(strings.TrimSpace(node.attrs["validation"]), "HMACSHA256")}
	if decryptionKey := strings.TrimSpace(node.attrs["decryption_key"]); machineDecryptionKeyPattern.MatchString(decryptionKey) {
		parts = append(parts, "decryptionKey="+decryptionKey, "decryption="+firstNonEmpty(strings.TrimSpace(node.attrs["decryption"]), "Auto"))
	}
	add(Candidate{Verification: Confirmed, CredentialType: "machine_key", Value: strings.Join(parts, ";"), ValidationBasis: machineKeyBasis})
}

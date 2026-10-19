package credentialanalysis

import (
	"strconv"
	"strings"
)

const maxNetNTLMv2BlobLength = 4096

// harvestNetNTLMRecord recognizes only the two bounded capture grammars
// supported by this batch. Returning true for a capture-shaped malformed row
// prevents generic assignment harvesting from reinterpreting its fields.
func harvestNetNTLMRecord(line string, lineNumber int, add func(Candidate)) bool {
	fields := strings.Split(line, ":")
	if len(fields) != 6 || fields[1] != "" {
		return false
	}
	// Both approved grammars have six colon-separated fields. Their response
	// shapes are deliberately distinct, so malformed capture-shaped rows are
	// still consumed without falling through to generic assignment parsing.
	if validHexLength(strings.TrimSpace(fields[3]), 48) && validHexLength(strings.TrimSpace(fields[4]), 48) {
		return harvestNetNTLMv1(fields, lineNumber, add)
	}
	return harvestNetNTLMv2(fields, lineNumber, add)
}

func harvestNetNTLMv1(fields []string, lineNumber int, add func(Candidate)) bool {
	if fields[1] != "" {
		return true
	}
	user, domain := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[2])
	lmResponse := strings.ToLower(strings.TrimSpace(fields[3]))
	ntResponse := strings.ToLower(strings.TrimSpace(fields[4]))
	challenge := strings.ToLower(strings.TrimSpace(fields[5]))
	if !meaningfulHashIdentity(user) || !meaningfulHashIdentity(domain) ||
		!validHexLength(lmResponse, 48) || !validHexLength(ntResponse, 48) ||
		!validHexLength(challenge, 16) {
		return true
	}
	add(Candidate{
		Verification:    Confirmed,
		CredentialType:  "netntlmv1",
		Identity:        user,
		Domain:          domain,
		Value:           strings.Join([]string{user, "", domain, lmResponse, ntResponse, challenge}, ":"),
		ValidationBasis: "structured_netntlmv1_record",
		Evidence:        []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}},
	})
	return true
}

func harvestNetNTLMv2(fields []string, lineNumber int, add func(Candidate)) bool {
	user, domain := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[2])
	challenge := strings.ToLower(strings.TrimSpace(fields[3]))
	proof := strings.ToLower(strings.TrimSpace(fields[4]))
	blob := strings.ToLower(strings.TrimSpace(fields[5]))
	return harvestNetNTLMv2Fields(user, domain, challenge, proof, blob, lineNumber, add)
}

func harvestNetNTLMv2Fields(user, domain, challenge, proof, blob string, lineNumber int, add func(Candidate)) bool {
	if !meaningfulHashIdentity(user) || !meaningfulHashIdentity(domain) ||
		!validHexLength(challenge, 16) || !validHexLength(proof, 32) ||
		len(blob) < 16 || len(blob) > maxNetNTLMv2BlobLength || len(blob)%2 != 0 ||
		!validHexLength(blob, len(blob)) || !strings.HasPrefix(blob, "01010000") {
		return true
	}
	add(Candidate{
		Verification:    Confirmed,
		CredentialType:  "netntlmv2",
		Identity:        user,
		Domain:          domain,
		Value:           strings.Join([]string{user, "", domain, challenge, proof + ":" + blob}, ":"),
		ValidationBasis: "structured_netntlmv2_record",
		Evidence:        []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}},
	})
	return true
}

func validHexLength(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !isHexRune(r) {
			return false
		}
	}
	return true
}

package credentialanalysis

import (
	"strconv"
	"strings"
)

const (
	maxCaptureRecordBytes = 64 << 10
	maxDCC2Iterations     = 1_000_000
)

// harvestCaptureRecord consumes lines belonging to an approved capture grammar.
// A recognized prefix is consumed even when malformed so generic assignment
// harvesting cannot reinterpret the line as a different credential type.
func harvestCaptureRecord(line string, lineNumber int, add func(Candidate)) bool {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "$krb5asrep$"):
		if candidate, ok := parseASREPRecord(line, lineNumber); ok {
			add(candidate)
		}
		return true
	case strings.HasPrefix(line, "$krb5tgs$"):
		if candidate, ok := parseTGSRecord(line, lineNumber); ok {
			add(candidate)
		}
		return true
	case strings.HasPrefix(line, "$DCC1#"):
		if candidate, ok := parseDCC1Record(line, lineNumber); ok {
			add(candidate)
		}
		return true
	case strings.HasPrefix(line, "$DCC2$"):
		if candidate, ok := parseDCC2Record(line, lineNumber); ok {
			add(candidate)
		}
		return true
	default:
		return false
	}
}

func parseASREPRecord(line string, lineNumber int) (Candidate, bool) {
	var zero Candidate
	if len(line) > maxCaptureRecordBytes {
		return zero, false
	}
	parts := strings.SplitN(line, "$", 4)
	if len(parts) != 4 || parts[0] != "" || parts[1] != "krb5asrep" || parts[2] != "23" {
		return zero, false
	}
	principal, checksum, ciphertext, ok := splitKerberosPayload(parts[3], ':', '$')
	if !ok || !validKerberosPrincipal(principal) || !validHexLength(checksum, 32) || !validHexField(ciphertext, 32, maxCaptureRecordBytes) {
		return zero, false
	}
	identity, realm := splitKerberosPrincipal(principal)
	if identity == "" {
		return zero, false
	}
	return Candidate{
		Verification:    Confirmed,
		CredentialType:  "kerberos_asrep",
		Identity:        identity,
		Domain:          realm,
		Value:           line,
		ValidationBasis: "structured_kerberos_asrep_record",
		Evidence:        []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}},
	}, true
}

func parseTGSRecord(line string, lineNumber int) (Candidate, bool) {
	var zero Candidate
	if len(line) > maxCaptureRecordBytes {
		return zero, false
	}
	const prefix = "$krb5tgs$23$"
	if !strings.HasPrefix(line, prefix) {
		return zero, false
	}
	rest := strings.TrimPrefix(line, prefix)
	if !strings.HasPrefix(rest, "*") {
		return zero, false
	}
	rest = strings.TrimPrefix(rest, "*")
	principal, payload, ok := strings.Cut(rest, "*")
	if !ok {
		return zero, false
	}
	principalFields := strings.Split(principal, "$")
	if len(principalFields) != 3 {
		return zero, false
	}
	user, realm, service := principalFields[0], principalFields[1], principalFields[2]
	payload = strings.TrimPrefix(payload, "$")
	_, checksum, ciphertext, ok := splitKerberosPayload(payload, '$', 0)
	if !ok || !validKerberosField(user, '$', '*') || !validKerberosField(realm, '$', '*') || !validKerberosField(service, '$', '*') || !validHexLength(checksum, 32) || !validHexField(ciphertext, 32, maxCaptureRecordBytes) {
		return zero, false
	}
	return Candidate{
		Verification:    Confirmed,
		CredentialType:  "kerberos_tgs",
		Identity:        user,
		Domain:          realm,
		Value:           line,
		ValidationBasis: "structured_kerberos_tgs_record",
		Evidence:        []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}},
	}, true
}

func parseDCC1Record(line string, lineNumber int) (Candidate, bool) {
	var zero Candidate
	if len(line) > maxCaptureRecordBytes {
		return zero, false
	}
	parts := strings.Split(line, "#")
	if len(parts) != 3 || parts[0] != "$DCC1" || !validKerberosField(parts[1], '#', 0) || !validHexLength(parts[2], 32) {
		return zero, false
	}
	return Candidate{Verification: Confirmed, CredentialType: "dcc", Identity: parts[1], Value: line, ValidationBasis: "structured_dcc_record", Evidence: []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}}}, true
}

func parseDCC2Record(line string, lineNumber int) (Candidate, bool) {
	var zero Candidate
	if len(line) > maxCaptureRecordBytes {
		return zero, false
	}
	parts := strings.Split(line, "#")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "$DCC2$") || !validKerberosField(parts[1], '#', 0) || !validHexLength(parts[2], 32) {
		return zero, false
	}
	iterations, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "$DCC2$"), 10, 32)
	if err != nil || iterations < 1 || iterations > maxDCC2Iterations {
		return zero, false
	}
	return Candidate{Verification: Confirmed, CredentialType: "dcc2", Identity: parts[1], Value: line, ValidationBasis: "structured_dcc2_record", Evidence: []Evidence{{Location: "line " + strconv.Itoa(lineNumber)}}}, true
}

func splitKerberosPayload(value string, separator byte, alternate byte) (string, string, string, bool) {
	if separator == ':' {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			return "", "", "", false
		}
		cipher := strings.SplitN(parts[1], "$", 2)
		if len(cipher) != 2 {
			return "", "", "", false
		}
		return parts[0], cipher[0], cipher[1], true
	}
	parts := strings.SplitN(value, "$", 2)
	if len(parts) != 2 {
		return "", "", "", false
	}
	return "", parts[0], parts[1], true
}

func validHexField(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || len(value)%2 != 0 {
		return false
	}
	for _, r := range value {
		if !isHexRune(r) {
			return false
		}
	}
	return true
}

func validKerberosPrincipal(value string) bool {
	if !validKerberosField(value, ':', '$') {
		return false
	}
	_, realm := splitKerberosPrincipal(value)
	return realm != ""
}

func splitKerberosPrincipal(value string) (string, string) {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return value, ""
	}
	return parts[0], parts[1]
}

func validKerberosField(value string, forbidden ...byte) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r <= 0x20 {
			return false
		}
		for _, blocked := range forbidden {
			if byte(r) == blocked {
				return false
			}
		}
	}
	return true
}

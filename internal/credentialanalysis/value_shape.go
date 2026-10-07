package credentialanalysis

import (
	"strings"
	"unicode"
)

// NonSecretValueShape reports whether a candidate credential value is, by shape
// alone, a non-secret fragment rather than a scalar secret. It is deliberately
// path-, vendor- and language-independent: callers may apply it to any file.
//
// The predicate rejects values that are structurally:
//
//   - SQL variables or bind/parameter references ("@var", ":bind")
//   - function calls or parenthesised expressions ("func(arg)")
//   - schema/column metadata definitions ("field,,type(n)")
//   - bare logical/operator fragments ("value and")
//   - prose sentences or label text ("plain words here")
//
// It never applies an entropy or length floor, so short literal credentials
// stay reachable. When it rejects a value it returns a short machine-readable
// reason; otherwise the reason is empty.
func NonSecretValueShape(value string) (string, bool) {
	inner := strings.TrimSpace(value)
	if inner == "" {
		return "", false
	}
	// A value may be wrapped in a single pair of quotes; unwrap it so the shape
	// checks see the actual token. Quoting is not treated as proof of a secret,
	// only as syntax to strip.
	if len(inner) >= 2 {
		first, last := inner[0], inner[len(inner)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			inner = strings.TrimSpace(inner[1 : len(inner)-1])
		}
	}
	if inner == "" {
		return "", false
	}

	// SQL variables, host variables and bind parameters.
	if strings.HasPrefix(inner, "@") || strings.HasPrefix(inner, "::") {
		return "sql_variable_or_parameter", true
	}
	if isBindParameter(inner) {
		return "sql_bind_parameter", true
	}

	// Function calls and parenthesised expressions. A literal credential does
	// not contain parentheses; SQL expressions and definitions routinely do.
	if strings.ContainsAny(inner, "()") {
		return "expression_or_function_call", true
	}

	// Comma-delimited metadata / schema definitions.
	if strings.Contains(inner, ",,") || strings.Count(inner, ",") >= 2 {
		return "schema_metadata_definition", true
	}

	fields := strings.Fields(inner)
	if len(fields) <= 1 {
		return "", false
	}
	if containsSQLLogicToken(fields) {
		return "sql_logic_fragment", true
	}
	if len(fields) >= 3 {
		return "prose_or_label_fragment", true
	}
	if allWordTokens(fields) {
		return "prose_sentence", true
	}
	return "", false
}

func isBindParameter(value string) bool {
	if len(value) < 2 || value[0] != ':' {
		return false
	}
	if value[1] == '/' || value[1] == ':' {
		// URL scheme separators ("://") are not bind parameters.
		return false
	}
	for _, r := range value[1:] {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			continue
		}
		return false
	}
	return true
}

var sqlLogicTokens = map[string]struct{}{
	"or": {}, "and": {}, "not": {}, "in": {}, "is": {}, "null": {}, "like": {},
	"between": {}, "case": {}, "when": {}, "then": {}, "else": {}, "select": {},
	"from": {}, "where": {}, "union": {}, "join": {}, "on": {}, "as": {},
	"exists": {}, "declare": {}, "set": {}, "exec": {}, "execute": {}, "go": {},
	"begin": {}, "end": {}, "if": {}, "into": {}, "values": {}, "create": {},
	"drop": {}, "alter": {}, "table": {}, "constraint": {}, "primary": {},
}

func containsSQLLogicToken(fields []string) bool {
	for _, field := range fields {
		token := strings.ToLower(strings.Trim(field, ".,;:!?()'\""))
		if _, ok := sqlLogicTokens[token]; ok {
			return true
		}
	}
	return false
}

// allWordTokens reports whether every whitespace-separated token is a plain
// word once surrounding punctuation is trimmed. Such multi-token values are
// prose or labels, never a scalar credential.
func allWordTokens(fields []string) bool {
	for _, field := range fields {
		trimmed := strings.Trim(field, ".,;:!?()'\"-")
		if trimmed == "" {
			return false
		}
		hasLetter := false
		for _, r := range trimmed {
			switch {
			case unicode.IsLetter(r):
				hasLetter = true
			case r == '\'' || r == '\u2019' || r == '-':
				// Apostrophes and hyphens join letters inside ordinary words
				// ("don't", "well-known").
			default:
				return false
			}
		}
		if !hasLetter {
			return false
		}
	}
	return true
}

// IsScalarCredentialType reports whether a candidate credential type carries a
// scalar secret value for which NonSecretValueShape is meaningful. Composite or
// structured material (private keys, whole connection strings, recovered NT
// hashes) is excluded.
func IsScalarCredentialType(credentialType string) bool {
	switch strings.ToLower(strings.TrimSpace(credentialType)) {
	case "", "private_key", "connection_string", "nt_hash", "certificate":
		return false
	default:
		return true
	}
}

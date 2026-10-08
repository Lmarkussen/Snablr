package credentialanalysis

import (
	"encoding/base64"
	"math"
	"strings"
	"unicode"
)

// This file centralises value-shape validation for candidate credentials. A
// credential-like *label* is never sufficient on its own: the right-hand value
// must, by its own shape, be plausible secret material. The predicates below
// are language-, vendor- and path-independent so they can be applied to any
// document a caller chooses to inspect.

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

// IsTokenSecretType reports whether a credential type denotes a bearer-style
// opaque secret (token, API key, secret key) for which a token/API-key value
// shape is required, as opposed to a password or a composite artifact.
func IsTokenSecretType(credentialType string) bool {
	switch strings.ToLower(strings.TrimSpace(credentialType)) {
	case "token", "bearer_token", "api_key", "api_secret", "access_key",
		"secret_key", "client_secret", "secret":
		return true
	default:
		return false
	}
}

// tokenPrefixes are well-known token/API-key prefixes. Their presence is strong,
// format-specific evidence that a value is a credential rather than ordinary
// metadata, a cache entry or structured text.
var tokenPrefixes = []string{
	"AKIA", "ASIA", "AIDA", "AROA", // AWS access key identifiers
	"eyJ",                                                 // JSON Web Token header (base64url of "{")
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"glpat-",                                    // GitLab
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", // Slack
	"ya29.", "1//0", // Google OAuth
	"AIza",                        // Google API key
	"sk-", "sk_live_", "sk_test_", // generic / Stripe secret keys
	"pk_live_", "pk_test_", "rk_live_", // Stripe public/restricted keys
	"SG.",     // SendGrid
	"whsec_",  // webhook signing secret
	"shpat_",  // Shopify
	"npm_",    // npm
	"pypi-",   // PyPI
	"dop_v1_", // DigitalOcean
	"secret_", // Notion
	"hf_",     // Hugging Face
	"rj_",     // generic
	"pat_",    // generic personal access token
}

// TokenSecretValueShape reports whether a value has structural, format-level
// evidence of being a token, API key or secret. It never treats entropy alone
// as proof: a value must either carry a recognised token prefix, be a
// structured JWT/JWE, or be an opaque API-key-shaped scalar that also survives
// the non-secret exclusions (URLs, paths, UUIDs, prose, structured fragments).
//
// When the value is not plausible token material it returns a short
// machine-readable reason; otherwise the reason is empty.
func TokenSecretValueShape(value string) (string, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "empty_value", false
	}
	inner := trimOneQuoting(raw)
	if inner == "" {
		return "empty_value", false
	}
	if looksReferenceOrTemplate(inner) {
		return "template_or_placeholder", false
	}
	if IsMaskedValue(inner) {
		return "masked_value", false
	}
	if strings.ContainsAny(inner, " \t\r\n") {
		return "contains_whitespace", false
	}
	if strings.ContainsAny(inner, "<>{}[]\"'`\\|;,") {
		return "structured_or_label_fragment", false
	}
	if looksLikePathOrURL(inner) {
		return "path_or_url", false
	}
	for _, prefix := range tokenPrefixes {
		if strings.HasPrefix(inner, prefix) {
			return "", true
		}
	}
	if isJWTShape(inner) {
		return "", true
	}
	if isOpaqueAPIKeyShape(inner) {
		return "", true
	}
	return "no_token_evidence", false
}

// IsMaskedValue reports whether a value is an explicit redaction placeholder
// rather than a real secret (for example a run of asterisks or a bracketed
// "redacted" marker).
func IsMaskedValue(value string) bool {
	trimmed := strings.TrimSpace(strings.Trim(value, `"'`))
	if trimmed == "" {
		return false
	}
	switch strings.ToLower(trimmed) {
	case "redacted", "[redacted]", "<redacted>", "(redacted)", "hidden", "masked":
		return true
	}
	// A run of identical mask characters ("********", "########", "••••"),
	// optionally wrapped in angle brackets.
	if len(trimmed) >= 3 {
		if strings.EqualFold(trimmed, "<password>") || strings.EqualFold(trimmed, "<secret>") ||
			strings.EqualFold(trimmed, "<token>") || strings.EqualFold(trimmed, "<pwd>") {
			return true
		}
		if isRunOfMaskRune(trimmed) {
			return true
		}
	}
	return false
}

func isRunOfMaskRune(value string) bool {
	runes := []rune(value)
	var mask rune
	for _, r := range runes {
		switch r {
		case '*', '#', '•', '\u25cf':
			if mask == 0 {
				mask = r
			} else if r != mask {
				return false
			}
		default:
			return false
		}
	}
	return mask != 0 && len(runes) >= 3
}

func trimOneQuoting(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

// looksLikePathOrURL reports whether a value is a filesystem path, UNC path or
// URL rather than a scalar secret.
func looksLikePathOrURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "://") {
		return true
	}
	if strings.HasPrefix(trimmed, "\\\\") || strings.HasPrefix(trimmed, "//") {
		return true
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") {
		return true
	}
	// Windows drive-letter path (C:\...) or a rooted backslash path.
	if len(trimmed) >= 3 && trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/') {
		return true
	}
	if strings.Contains(trimmed, "\\") {
		return true
	}
	return false
}

func isJWTShape(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 && len(parts) != 5 {
		return false
	}
	for _, part := range parts {
		if part == "" || !isBase64URLSegment(part) {
			return false
		}
	}
	// The header segment of a JWT is base64url-encoded JSON. Require that the
	// first segment decodes to a JSON object so a dotted random string does not
	// qualify.
	header, ok := decodeBase64URL(parts[0])
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(string(header))
	return strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")
}

func isBase64URLSegment(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			continue
		case r == '-' || r == '_' || r == '=':
			continue
		default:
			return false
		}
	}
	return true
}

func decodeBase64URL(value string) ([]byte, bool) {
	// Both padded and unpadded base64url are accepted.
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

// isOpaqueAPIKeyShape reports whether a value is a sufficiently long, opaque,
// mixed-alphabet scalar that plausibly represents an API key or token. Entropy
// is only supporting evidence: the value must also be alphabetically mixed and
// must not resemble a UUID, prose or a hash-like identifier.
func isOpaqueAPIKeyShape(value string) bool {
	length := len(value)
	if length < 20 || length > 512 {
		return false
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '-' || r == '_' || r == '.' || r == '~' || r == '+' || r == '/' || r == '=':
			hasSymbol = true
		default:
			return false
		}
	}
	if !hasLower || !hasDigit {
		// A token that is only one alphabet (for example all letters) or lacks
		// digits is too unstructured to distinguish from an ordinary word.
		return false
	}
	// Require at least two distinct character classes, and demand either a third
	// class (upper case or symbol) or a clearly credential-length all-lowercase
	// mixed-alpha-numeric value. This keeps long opaque secrets reachable
	// without accepting short identifiers or ordinary lowercase words.
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			classes++
		}
	}
	if classes < 3 && !(hasDigit && length >= 24) {
		return false
	}
	if isUUIDLike(value) {
		return false
	}
	if uniqueTokenRunes(value) < 8 {
		return false
	}
	if tokenEntropy(value) < 3.0 {
		return false
	}
	return true
}

func uniqueTokenRunes(value string) int {
	seen := make(map[rune]struct{})
	for _, r := range value {
		seen[r] = struct{}{}
	}
	return len(seen)
}

func tokenEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	freq := make(map[rune]float64)
	total := 0.0
	for _, r := range value {
		freq[r]++
		total++
	}
	entropy := 0.0
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isUUIDLike(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexRune(r) {
				return false
			}
		}
	}
	return true
}

func isHexRune(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

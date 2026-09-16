package credentialanalysis

import (
	"regexp"
	"strings"
	"unicode"
)

// Natural-language credential expressions.
//
// Real documents often state a credential as a sentence rather than as a
// machine assignment:
//
//	Passordet er; Hemmelig-123!
//	Password is; Secret123!
//
// Recognising these requires a bounded grammar, not a general NLP engine and not
// a global ";" operator (which would turn ordinary prose into credentials):
//
//	<credential label> <connector> [separator] <bounded value token>
//
// The label is classified by the shared semantic layer, the connector must be a
// grammatical copula ("er"/"is"), the separator is one of a small set, and the
// value must be a single token that carries credential evidence. Recognised
// expressions are rewritten into the ordinary assignment form so every existing
// consumer (harvester, content rules, post-scan analysis) keeps working
// unchanged.

// naturalLanguageExpression matches one label, one copula connector, an optional
// separator, and the remaining value text on the line.
var naturalLanguageExpression = regexp.MustCompile(`(?i)^\s*([\p{L}][\p{L}\p{N}_.-]{1,31})\s+(er|is)\s*([:;=\-]?)\s*(.*)$`)

// naturalLanguageStopwords are grammatical/function words that are never a
// credential value on their own.
var naturalLanguageStopwords = map[string]struct{}{
	"en": {}, "et": {}, "ei": {}, "den": {}, "det": {}, "de": {}, "som": {}, "for": {}, "og": {}, "eller": {},
	"a": {}, "an": {}, "the": {}, "to": {}, "of": {}, "for ": {}, "and": {}, "or": {},
}

// NormalizeCredentialExpressions rewrites recognised natural-language credential
// expressions into the shared assignment form, leaving every other line
// untouched. It is idempotent and safe for arbitrary text.
func NormalizeCredentialExpressions(text string) string {
	if text == "" || !containsCredentialLabelWord(text) {
		return text
	}
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		match := naturalLanguageExpression.FindStringSubmatch(line)
		if match == nil {
			out = append(out, line)
			continue
		}
		label, connector := match[1], match[2]
		role := ClassifyFieldName(label)
		if role == FieldRoleNone {
			out = append(out, line)
			continue
		}
		if !isCopulaConnector(connector) {
			out = append(out, line)
			continue
		}
		value := strings.TrimSpace(match[4])
		if value == "" {
			// Bounded two-line form: the value is the immediately following line.
			// A blank line is a paragraph boundary and is never crossed.
			if index+1 < len(lines) {
				next := strings.TrimSpace(lines[index+1])
				if next != "" && !naturalLanguageExpression.MatchString(next) {
					if acceptsNaturalLanguageValue(role, next) {
						out = append(out, canonicalExpressionLabel(role, label)+"="+next)
						index++
						continue
					}
				}
			}
			out = append(out, line)
			continue
		}
		if !acceptsNaturalLanguageValue(role, value) {
			out = append(out, line)
			continue
		}
		out = append(out, canonicalExpressionLabel(role, label)+"="+value)
	}
	return strings.Join(out, "\n")
}

// canonicalExpressionLabel maps the inflected label phrase onto the base token the
// shared assignment grammar recognises, keeping the document's language:
// "Passordet" becomes "Passord" (not "Password").
func canonicalExpressionLabel(role FieldRole, label string) string {
	lower := strings.ToLower(strings.TrimSpace(label))
	switch role {
	case FieldRolePassword:
		switch {
		case strings.Contains(lower, "passord"):
			return "Passord"
		case strings.Contains(lower, "passwd"):
			return "Passwd"
		case strings.Contains(lower, "pwd"):
			return "Pwd"
		default:
			return "Password"
		}
	case FieldRoleIdentity:
		if strings.Contains(lower, "bruker") || strings.Contains(lower, "konto") {
			return "Brukernavn"
		}
		return "Username"
	case FieldRoleDomain:
		if strings.Contains(lower, "domene") {
			return "Domene"
		}
		return "Domain"
	default:
		return label
	}
}

func isCopulaConnector(connector string) bool {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "er", "is":
		return true
	default:
		return false
	}
}

// containsCredentialLabelWord is a cheap pre-filter so documents without any
// credential vocabulary are returned untouched.
func containsCredentialLabelWord(text string) bool {
	lower := strings.ToLower(text)
	for _, word := range []string{"passord", "password", "passwd", "pwd", "bruker", "user", "konto", "account", "domene", "domain", "login"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// acceptsNaturalLanguageValue reports whether a candidate value is bounded
// enough to be treated as credential material. It deliberately accepts only a
// single token: prose policy sentences are multi-word and are never a value.
func acceptsNaturalLanguageValue(role FieldRole, value string) bool {
	value = strings.TrimRight(strings.TrimSpace(value), ".,;:")
	if value == "" || looksReferenceOrTemplate(value) {
		return false
	}
	if strings.ContainsAny(value, " \t") {
		return false
	}
	if _, stopword := naturalLanguageStopwords[strings.ToLower(value)]; stopword {
		return false
	}
	switch role {
	case FieldRolePassword:
		return looksLikeCredentialToken(value)
	case FieldRoleIdentity:
		if len(value) < 3 || len(value) > 64 {
			return false
		}
		return hasAccountShape(value) || looksLikeCredentialToken(value)
	case FieldRoleDomain:
		if len(value) < 3 || len(value) > 64 {
			return false
		}
		return hasDomainShape(value)
	default:
		return false
	}
}

// looksLikeCredentialToken requires evidence that a token is credential material
// rather than a policy word: a digit, a symbol, or mixed case.
func looksLikeCredentialToken(value string) bool {
	if len(value) < 6 || len(value) > 128 {
		return false
	}
	var hasDigit, hasSymbol, hasUpper, hasLower bool
	for _, r := range value {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsLetter(r):
			// letters without case information (e.g. CJK) count as letters only
		default:
			hasSymbol = true
		}
	}
	if hasDigit || hasSymbol {
		return true
	}
	return hasUpper && hasLower
}

// hasAccountShape recognises the punctuation and separators common in account
// names (svc_backup, backup-tjeneste, user1, DOMAIN\\user, user@domain).
func hasAccountShape(value string) bool {
	if !hasPlainTokenCharacters(value) {
		return false
	}
	return strings.ContainsAny(value, `._-@\`) || containsDigit(value)
}

// hasDomainShape recognises DNS/NetBIOS-style domain names.
func hasDomainShape(value string) bool {
	if !hasPlainTokenCharacters(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func hasPlainTokenCharacters(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '-', '_', '@', '\\', '$', '+':
			continue
		default:
			return false
		}
	}
	return true
}

func containsDigit(value string) bool {
	for _, r := range value {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

package credentialanalysis

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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
//	[prefix] <credential label> [subject phrase] <connector> [separator] <value>
//
// The label is classified by the shared semantic layer, the connector must be a
// grammatical copula ("er"/"is"), the separator is one of a small set, and the
// value must be the final token on the logical line and carry credential
// evidence. A bounded expression may follow ordinary prefix text, and a single
// short subject token may sit between the label and the copula, so phrases such
// as "Passordet for nettverket er; X" are reachable without loosening the
// grammar into prose. Recognised expressions are rewritten into the ordinary
// assignment form so every existing consumer (harvester, content rules,
// post-scan analysis) keeps working unchanged.

// naturalLanguageExpression matches one label, one copula connector, an optional
// bounded subject phrase, an optional separator, and the trailing value token.
//
// Groups: 1 leading boundary, 2 label, 3 subject phrase, 4 copula, 5 separator,
// 6 value. The value group is absent only for the bounded two-line form, where
// the value is the next line.
//
// Only whitespace and one optional separator may stand between the copula and
// the value, and the value must run to the end of the line. That structural
// bound - not password "strength" - is what keeps ordinary prose and policy
// sentences out, so short weak values stay reachable.
var naturalLanguageExpression = regexp.MustCompile(`(?i)(^|[^\p{L}\p{N}_.-])([\p{L}][\p{L}\p{N}_.-]{1,31})((?:\s+for\s+[\p{L}][\p{L}\p{N}_.-]{0,31})?)\s+(er|is)\s*([:;=\-]?)\s*(\S+)?\s*$`)

// explicitPasswordMinimumRunes is the smallest value accepted in strong explicit
// password syntax. The generic inference floor is higher, but an explicit
// "<password label> <copula> <value>" statement is a deliberate assertion of a
// credential: poor, short, all-digit and PIN-like credentials are exactly what
// has to be discovered, so the bound is aligned with the existing content rule,
// which already accepts four-character assignment values.
const explicitPasswordMinimumRunes = 4

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
		match := naturalLanguageExpression.FindStringSubmatchIndex(line)
		if match == nil {
			out = append(out, line)
			continue
		}
		label := line[match[4]:match[5]]
		connector := line[match[8]:match[9]]
		role := ClassifyFieldName(label)
		if role == FieldRoleNone {
			out = append(out, line)
			continue
		}
		if !isCopulaConnector(connector) {
			out = append(out, line)
			continue
		}
		value := ""
		if match[12] >= 0 {
			value = line[match[12]:match[13]]
		}
		value = strings.TrimSpace(value)
		if value == "" {
			// Bounded two-line form: the value is the immediately following line.
			// A blank line is a paragraph boundary and is never crossed.
			if index+1 < len(lines) {
				next := strings.TrimSpace(lines[index+1])
				if next != "" && !naturalLanguageExpression.MatchString(next) {
					if acceptsNaturalLanguageValue(role, next) {
						out = append(out, rewriteExpression(line, match[4], role, label)+"="+expressionValue(next))
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
		out = append(out, rewriteExpression(line, match[4], role, label)+"="+expressionValue(value))
	}
	return strings.Join(out, "\n")
}

// rewriteExpression replaces the matched expression with the shared assignment
// form, keeping whatever preceded the credential label.
//
// The shared assignment representation is line-oriented: the line harvester,
// configuration sections and correlation all read an assignment that starts its
// logical line. When a lead-in sentence precedes the label, the assignment is
// therefore emitted on its own line so the prose can never be read as part of
// the value.
func rewriteExpression(line string, labelStart int, role FieldRole, label string) string {
	prefix := line[:labelStart]
	assignment := canonicalExpressionLabel(role, label)
	if strings.TrimSpace(prefix) == "" {
		return prefix + assignment
	}
	return strings.TrimRight(prefix, " \t") + "\n" + assignment
}

// expressionValue strips the sentence punctuation that terminates a
// natural-language value. The grammar has already bounded the value to a single
// trailing token.
func expressionValue(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), ".,;:")
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
		return acceptsExplicitPasswordValue(value)
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

// acceptsExplicitPasswordValue applies the value-quality rule for strong explicit
// password syntax. Unlike generic token inference it does not impose the
// six-rune floor. Bounded structure still has to hold: one token, not empty, not
// a template/reference/stopword, and at least one character that carries
// credential evidence.
func acceptsExplicitPasswordValue(value string) bool {
	count := utf8.RuneCountInString(value)
	if count < explicitPasswordMinimumRunes || count > 128 {
		return false
	}
	return passwordValueEvidence(value)
}

// passwordValueEvidence reports whether a token carries structural evidence of
// being credential material rather than a policy word or a compound prose term:
// a digit, a non-connector symbol, or mixed case. Connector characters are how
// prose compounds such as "case-sensitive" are written, so they are not evidence
// on their own.
func passwordValueEvidence(value string) bool {
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
		case strings.ContainsRune(`-_.\/@`, r):
		default:
			hasSymbol = true
		}
	}
	if hasDigit || hasSymbol {
		return true
	}
	return hasUpper && hasLower
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

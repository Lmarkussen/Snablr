package credentialanalysis

import (
	"regexp"
	"strings"
)

// This file centralises structural placeholder / template detection.
//
// A placeholder is never credential material: recognised templates and
// placeholders are excluded from every credential output (confirmed material,
// review material and the explicit sensitive creds export) rather than being
// carried forward as a lower-confidence candidate.
//
// Detection is deliberately structural and context-aware. It never treats every
// uppercase value as a placeholder: a real password may be uppercase, may be
// short, may be a dictionary word and may end in a period. The predicates below
// only recognise wrapper syntax, explicit template vocabulary used as whole
// tokens, and symbolic ALL-CAPS underscore identifier shapes.

var (
	percentWrapperPattern = regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_.-]*%$`)
	shellWrapperPattern   = regexp.MustCompile(`^\$\{[^{}]*\}$`)
	handlebarsPattern     = regexp.MustCompile(`^\{\{[^{}]*\}\}$`)
	angleWrapperPattern   = regexp.MustCompile(`^<[A-Za-z_][A-Za-z0-9_ .-]*>$`)
	symbolicPattern       = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	alphabeticOnlyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z_\- ]*$`)
	// scriptVariablePattern is a PowerShell/shell variable reference with
	// optional property access, scope and trailing call parentheses:
	// "$clearText", "$Value.UserName", "$env:APP_PASSWORD", "$Password.Password))".
	scriptVariablePattern = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)((?:[.:][A-Za-z_][A-Za-z0-9_]*)*)(\)*)$`)
)

// redactionMarkers are values that tools write in place of a removed secret.
// Windows setup replaces unattend passwords with "*SENSITIVE*DATA*DELETED*".
var redactionMarkers = map[string]struct{}{
	"*sensitive*data*deleted*": {},
}

// fieldNameEchoes are credential field names written in capitals as the value
// of the field itself ("USERNAME" : "PASSWORD" in usage text). Only the
// all-capitals form is a placeholder: a lowercase "password" can be a real,
// weak password.
var fieldNameEchoes = map[string]struct{}{
	"PASSWORD": {}, "PASSWD": {}, "PWD": {}, "SECRET": {},
	"USERNAME": {}, "USER": {}, "USERID": {}, "LOGIN": {},
}

// scriptVariableWords mark a bare "$name" as a variable rather than a secret
// that happens to start with "$".
var scriptVariableWords = []string{"pass", "pwd", "secret", "token", "cred", "key", "user", "login", "account", "text", "value", "plain", "clear", "string"}

// templateTokenWords are tokens that carry explicit template vocabulary even
// when combined with other tokens. They are matched as complete tokens (never
// as substrings) and only when the value contains no digits or other symbols,
// so an ordinary credential such as "Contest2026!" or "ExampleCorp482!"
// survives while "YOUR_PASSWORD", "REPLACE_ME" and "PASSWORD_TEMPLATE" are
// recognised.
//
// Ambiguous dictionary words (test, default, demo, fake, admin, sample,
// example) are deliberately absent here: a real credential or account name may
// legitimately combine them ("svc_example"). They are only treated as templates
// when they make up the entire value.
var templateTokenWords = map[string]struct{}{
	"replace":        {},
	"replaceme":      {},
	"replaceit":      {},
	"your":           {},
	"changeme":       {},
	"changepassword": {},
	"template":       {},
	"placeholder":    {},
	"fixme":          {},
	"todo":           {},
	"setme":          {},
	"insert":         {},
	"enter":          {},
}

// wholeValueTemplateWords are ambiguous template words that only mark a value as
// a placeholder when they are the entire value (for example "EXAMPLE"), never
// when they are one token of a larger value.
var wholeValueTemplateWords = map[string]struct{}{
	"example": {}, "sample": {}, "dummy": {}, "changeme": {}, "placeholder": {},
	"template": {}, "replace_me": {}, "replace-me": {}, "yoursecret": {}, "yourpassword": {},
}

// nonSecretLiterals are bare language/policy values that describe the absence of
// a secret rather than a secret value.
var nonSecretLiterals = map[string]struct{}{
	"null": {}, "nil": {}, "none": {}, "undefined": {}, "true": {}, "false": {},
}

// PlaceholderReason reports whether a value is structurally a placeholder or
// template rather than usable credential material. When it is, a short
// machine-readable reason is returned; otherwise the reason is empty.
//
// The predicate is applied to values in a credential position. It never
// suppresses a value merely for being uppercase, short, low entropy or
// dictionary-like.
func PlaceholderReason(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	inner := trimOneQuoting(trimmed)
	if inner == "" {
		return "", false
	}
	if IsMaskedValue(inner) {
		return "masked_value", true
	}
	if reason, ok := scalarPlaceholderReason(inner); ok {
		return reason, true
	}
	if compositePlaceholder(inner) {
		return "template_composite", true
	}
	return "", false
}

// IsPlaceholderValue reports whether a candidate credential value is a
// recognised placeholder or template.
func IsPlaceholderValue(value string) bool {
	_, ok := PlaceholderReason(value)
	return ok
}

// IsPlaceholderIdentity reports whether an account identity is itself symbolic
// or template material (for example "%APP_USER%", "${SERVICE_USER}" or
// "USER_TEMPLATE"). When an identity is a placeholder it must never be used to
// confirm a password candidate.
func IsPlaceholderIdentity(identity string) bool {
	unquoted := strings.TrimSpace(identity)
	for trimmed := trimOneQuoting(unquoted); trimmed != unquoted; trimmed = trimOneQuoting(unquoted) {
		unquoted = trimmed
	}
	// An account named after the field itself ("username : password" in
	// usage text) is never a real account, in any letter case.
	if _, ok := identityFieldNames[strings.ToLower(unquoted)]; ok {
		return true
	}
	// A variable, parameter or type reference is code, never an account.
	if IsCodeReference(unquoted) {
		return true
	}
	return IsPlaceholderValue(identity)
}

var identityFieldNames = map[string]struct{}{
	"username": {}, "user": {}, "userid": {}, "user_name": {}, "login": {}, "account": {}, "accountname": {},
}

// scalarPlaceholderReason classifies a single (non-composite) value.
func scalarPlaceholderReason(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	for unquoted := trimOneQuoting(trimmed); unquoted != trimmed; unquoted = trimOneQuoting(trimmed) {
		trimmed = unquoted
	}
	if trimmed == "" {
		return "", false
	}
	if _, ok := redactionMarkers[strings.ToLower(trimmed)]; ok {
		return "redaction_marker", true
	}
	if _, ok := fieldNameEchoes[trimmed]; ok {
		return "field_name_echo", true
	}
	if isScriptVariableReference(trimmed) {
		return "variable_reference", true
	}
	if lower := strings.ToLower(trimmed); lower == "autogenerate" || lower == "autogenerate,isolateapps" {
		return "non_secret_literal", true
	}
	if _, ok := nonSecretLiterals[strings.ToLower(trimmed)]; ok {
		return "non_secret_literal", true
	}
	if _, ok := wholeValueTemplateWords[strings.ToLower(trimmed)]; ok {
		return "template_word", true
	}
	if percentWrapperPattern.MatchString(trimmed) ||
		shellWrapperPattern.MatchString(trimmed) ||
		handlebarsPattern.MatchString(trimmed) ||
		angleWrapperPattern.MatchString(trimmed) {
		return "template_wrapper", true
	}
	if symbolicPattern.MatchString(trimmed) && allSegmentsAlphabetic(trimmed) {
		return "symbolic_identifier", true
	}
	if alphabeticOnlyPattern.MatchString(trimmed) && containsTemplateWord(trimmed) {
		return "template_word", true
	}
	return "", false
}

// compositePlaceholder reports whether a delimiter-separated composite value
// (connection string, DSN or key/value list) is built entirely from placeholder
// material in its credential-bearing components. A composite that carries at
// least one real component is never treated as a placeholder.
func compositePlaceholder(value string) bool {
	if !strings.Contains(value, "=") {
		return false
	}
	if !strings.ContainsAny(value, ";&\n") {
		return false
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == '&' || r == '\n'
	})
	checked := 0
	for _, part := range parts {
		part = strings.TrimSpace(strings.Trim(part, `"'`))
		if part == "" {
			continue
		}
		separator := strings.IndexAny(part, "=:")
		if separator <= 0 {
			continue
		}
		key := normalizeKey(part[:separator])
		component := strings.TrimSpace(strings.Trim(part[separator+1:], `"'`))
		if component == "" || !isCredentialComponentKey(key) {
			continue
		}
		checked++
		if _, ok := scalarPlaceholderReason(component); !ok {
			return false
		}
	}
	return checked > 0
}

// isCredentialComponentKey reports whether a normalized key names an
// authentication-bearing component of a composite credential value.
func isCredentialComponentKey(key string) bool {
	switch key {
	case "server", "host", "data_source", "datasource", "address", "endpoint", "instance":
		return true
	}
	switch ClassifyFieldName(key) {
	case FieldRolePassword, FieldRoleIdentity:
		return true
	default:
		return false
	}
}

// allSegmentsAlphabetic reports whether every underscore-separated segment of an
// ALL-CAPS value consists solely of uppercase letters. A digit inside any
// segment (for example "ONLYUPPERCASE42" or "RUN_2026") keeps the value
// reachable as a real credential.
func allSegmentsAlphabetic(value string) bool {
	for _, segment := range strings.Split(value, "_") {
		if segment == "" {
			return false
		}
		for _, r := range segment {
			if r < 'A' || r > 'Z' {
				return false
			}
		}
	}
	return true
}

// isScriptVariableReference reports whether a value is a script variable
// reference rather than a secret: a "$name" with property access, a scope,
// trailing call parentheses, a language literal, or a name made of variable
// vocabulary. A value with digits or symbols after the name ("$ecret2026!")
// does not match.
func isScriptVariableReference(value string) bool {
	match := scriptVariablePattern.FindStringSubmatch(value)
	if match == nil {
		return false
	}
	name, access, calls := strings.ToLower(match[1]), match[2], match[3]
	if access != "" || calls != "" {
		return true
	}
	switch name {
	case "null", "true", "false":
		return true
	}
	for _, word := range scriptVariableWords {
		if strings.Contains(name, word) {
			return true
		}
	}
	return false
}

func containsTemplateWord(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if _, ok := templateTokenWords[token]; ok {
			return true
		}
	}
	return false
}

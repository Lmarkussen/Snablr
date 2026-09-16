package credentialanalysis

import (
	"sort"
	"strings"
)

// Credential-field semantics are expressed as language-neutral token families.
// Each family holds aliases that, after casing/separator/camel-case
// normalization, map a field-name token onto a canonical semantic role.
//
// Parsers and classifiers never branch on raw field names; they ask this layer
// for the semantic role of a key. Additional languages are supported by
// extending the alias tables below.

// passwordTokenAliases holds terminal tokens that denote a password value.
var passwordTokenAliases = map[string]struct{}{
	"password":  {},
	"passwd":    {},
	"pwd":       {},
	"passord":   {}, // Norwegian
	"passordet": {}, // Norwegian definite form ("the password")
}

// identityTokenAliases holds terminal tokens that denote an account identity.
var identityTokenAliases = map[string]struct{}{
	"user": {}, "username": {}, "login": {}, "account": {}, "email": {},
	"bruker": {}, "brukernavn": {}, "konto": {}, "kontonavn": {}, // Norwegian
}

// identityQualifierAliases are trailing tokens that only carry identity meaning
// when preceded by a recognized identity root (for example user_id, bruker_navn).
var identityQualifierAliases = map[string]struct{}{
	"id": {}, "name": {},
	"navn": {}, // Norwegian
}

// identityRootAliases are tokens that may be combined with a trailing qualifier
// to form an identity key. The English set is intentionally limited to "user"
// so existing behavior is preserved.
var identityRootAliases = map[string]struct{}{
	"user":   {},
	"bruker": {}, "konto": {}, // Norwegian
}

// domainTokenAliases holds terminal tokens that denote an authentication domain.
var domainTokenAliases = map[string]struct{}{
	"domain": {},
	"domene": {}, // Norwegian
}

// FieldRole is the canonical semantic role of a credential-like field name.
type FieldRole int

const (
	FieldRoleNone FieldRole = iota
	FieldRolePassword
	FieldRoleIdentity
	FieldRoleDomain
)

// fieldPriority orders normalized field names when several aliases for the same
// role appear in one record. More specific aliases are listed first. English
// aliases keep their established precedence; the fallback scan in
// SelectFieldValue remains deterministic for company-specific prefixes.
var fieldPriority = map[FieldRole][]string{
	FieldRolePassword: {"password", "passwd", "pwd", "passord"},
	FieldRoleIdentity: {
		"username", "user", "userid", "login", "account", "email",
		"brukernavn", "bruker_navn", "kontonavn", "konto_navn", "bruker", "konto",
	},
	FieldRoleDomain: {"domain", "domene"},
}

// ClassifyFieldName reports the semantic role of a raw credential field name.
// The name is normalized with the shared casing/separator/camel-case rules
// before classification.
func ClassifyFieldName(key string) FieldRole {
	tokens := keyTokens(key)
	if len(tokens) == 0 {
		return FieldRoleNone
	}
	last := tokens[len(tokens)-1]
	if _, ok := passwordTokenAliases[last]; ok {
		return FieldRolePassword
	}
	if _, ok := domainTokenAliases[last]; ok {
		return FieldRoleDomain
	}
	if _, ok := identityTokenAliases[last]; ok {
		return FieldRoleIdentity
	}
	if _, ok := identityQualifierAliases[last]; ok && len(tokens) >= 2 {
		if _, ok := identityRootAliases[tokens[len(tokens)-2]]; ok {
			return FieldRoleIdentity
		}
	}
	return FieldRoleNone
}

// SelectFieldValue returns the most specific non-empty value for the requested
// semantic role. Normalized field names are matched against the role priority
// list first, then a deterministic scan catches compound aliases such as
// "db_password" or "bruker_passord".
func SelectFieldValue(fields map[string]string, role FieldRole) string {
	if len(fields) == 0 {
		return ""
	}
	for _, key := range fieldPriority[role] {
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ClassifyFieldName(key) != role {
			continue
		}
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	return ""
}

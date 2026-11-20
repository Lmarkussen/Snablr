package credentialanalysis

import (
	"regexp"
	"strings"
)

// Source code mentions credentials through variables, parameters and type
// declarations far more often than through literal secrets:
//
//	login(module.params['login_user'], module.params['login_password'])
//	def connect(username: str, password: str)
//	[System.String] $Credential.UserName = [System.String] $null
//	user; password;
//
// Those fragments land in identity and value positions but are code, never
// an account or a secret, in any language.

var (
	// receiver.member or receiver['key'] / receiver[index], with at least
	// one index access, optionally followed by a list or statement separator.
	indexedAccessPattern = regexp.MustCompile(`^\$?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\s*(?:'[^']*'|"[^"]*"|\\"[^"\\]*\\"|\$?[A-Za-z0-9_.]+)\s*\])*\[\s*(?:'[^']*'|"[^"]*"|\\"[^"\\]*\\"|\$?[A-Za-z0-9_.]+)\s*\](?:\.[A-Za-z_][A-Za-z0-9_]*)*[,;]?$`)
	// receiver.member chains starting with a well-known receiver name.
	memberAccessPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)+[,;]?$`)
	// a bare identifier made of letters and underscores that ends with a
	// list or statement separator ("str,", "user;").
	separatedIdentifierPattern = regexp.MustCompile(`^[A-Za-z_]+[,;]$`)
	// "[user;]", "[password]" style placeholders.
	bracketedIdentifierPattern = regexp.MustCompile(`^\[\s*[A-Za-z_][A-Za-z0-9_]*\s*[,;]?\s*\]$`)
	// PowerShell typed values: "[System.String] $null", "[string]$Password".
	typedVariablePattern = regexp.MustCompile(`^\[[A-Za-z][A-Za-z0-9_.]*(?:\[\])?\]\s*(?:\$[A-Za-z_][A-Za-z0-9_.:]*|\$null)?[,;]?$`)
	// an empty string literal or a numeric constant followed by a list or
	// statement separator ("\"\",", "0x00000010,").
	emptyOrNumericLiteralPattern = regexp.MustCompile(`^(?:\\?"\\?"|''|0[xX][0-9A-Fa-f]+)[,;]$`)
	// lowercase snake_case variable names for a secret ("idrac_password",
	// "dummy_password", "api_pwd").
	secretVariableNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:password|passwd|pwd|pass|secret)$`)
)

// codeReceivers are object names that start a member access in code; a
// dotted value starting with one of them is a reference, not a secret.
var codeReceivers = map[string]struct{}{
	"self": {}, "cls": {}, "this": {}, "module": {}, "params": {}, "args": {}, "kwargs": {},
	"opts": {}, "options": {}, "config": {}, "conf": {}, "cfg": {}, "settings": {}, "request": {},
	"req": {}, "ctx": {}, "context": {}, "env": {}, "os": {}, "process": {}, "credential": {},
	"credentials": {}, "creds": {}, "cred": {}, "auth": {}, "form": {}, "payload": {}, "body": {},
	"input": {},
}

// typeNames are language type names that appear as the "value" of a
// credential parameter in signatures and API schemas.
var typeNames = map[string]struct{}{
	"str": {}, "string": {}, "int": {}, "integer": {}, "bool": {}, "boolean": {}, "securestring": {},
}

// IsCodeReference reports whether a value or identity is a code reference
// (a variable, parameter, member access or type name) rather than literal
// credential material. Such a value is never confirmed; it may still be kept
// as review material, like other unresolved references.
func IsCodeReference(value string) bool {
	_, ok := codeReferenceReason(value)
	return ok
}

// codeReferenceReason reports whether a value or identity is a code
// reference rather than literal credential material.
func codeReferenceReason(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	if _, ok := typeNames[strings.ToLower(strings.TrimRight(trimmed, ",;"))]; ok {
		return "type_name", true
	}
	switch {
	case indexedAccessPattern.MatchString(trimmed):
		return "code_index_access", true
	case emptyOrNumericLiteralPattern.MatchString(trimmed):
		return "code_literal", true
	case separatedIdentifierPattern.MatchString(trimmed):
		return "code_identifier", true
	case bracketedIdentifierPattern.MatchString(trimmed):
		return "code_identifier", true
	case typedVariablePattern.MatchString(trimmed):
		return "typed_variable", true
	case secretVariableNamePattern.MatchString(trimmed):
		return "variable_name", true
	}
	// A rule match can stop at a quote and leave "module.params[" or
	// "self.get(": a member access on a code receiver, cut off.
	if match := memberAccessPattern.FindStringSubmatch(strings.TrimRight(trimmed, "[(")); match != nil {
		if _, ok := codeReceivers[strings.ToLower(match[1])]; ok {
			return "code_member_access", true
		}
	}
	return "", false
}

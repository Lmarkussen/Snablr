package keyinspect

import "strings"

var exactPrivateKeyFiles = map[string]struct{}{
	"id_rsa":     {},
	"id_ed25519": {},
	"id_ecdsa":   {},
	"id_dsa":     {},
	"identity":   {},
}

var privateKeyHeaders = []string{
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN DSA PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
}

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(candidate Candidate) bool {
	_, ok := exactPrivateKeyFiles[normalizedName(candidate)]
	return ok
}

func normalizedName(candidate Candidate) string {
	return strings.ToLower(strings.TrimSpace(candidate.Name))
}

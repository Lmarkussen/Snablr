package keyinspect

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

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
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
}

const (
	StatusConfirmed = "confirmed"
	StatusEncrypted = "encrypted"
	StatusMalformed = "malformed"
	StatusReview    = "review"
)

func New() Inspector {
	return Inspector{}
}

func (Inspector) NeedsContent(candidate Candidate) bool {
	if _, ok := exactPrivateKeyFiles[normalizedName(candidate)]; ok {
		return true
	}
	ext := strings.ToLower(strings.TrimSpace(candidate.Extension))
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(strings.TrimSpace(candidate.Name)))
	}
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(strings.TrimSpace(candidate.FilePath)))
	}
	return ext == "" || ext == ".pem" || ext == ".key" || ext == ".priv" || ext == ".openssh"
}

func parsePrivateKey(content []byte, header string) (format, algorithm, status, reason string, encrypted bool) {
	block, _ := pem.Decode(content)
	if block == nil {
		return "", "", StatusMalformed, "private-key header has no valid PEM block", false
	}
	format = "PEM"
	if block.Type == "OPENSSH PRIVATE KEY" {
		format = "OpenSSH"
		algorithm = "OpenSSH"
		_, err := ssh.ParseRawPrivateKey(content)
		if err == nil {
			return format, algorithm, StatusConfirmed, "", false
		}
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return format, algorithm, StatusEncrypted, "encrypted OpenSSH private key", true
		}
		return format, algorithm, StatusMalformed, err.Error(), false
	}
	if x509.IsEncryptedPEMBlock(block) {
		return format, strings.TrimSuffix(block.Type, " PRIVATE KEY"), StatusEncrypted, "encrypted PEM private key", true
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if err := parseEncryptedPKCS8(block.Bytes); err != nil {
			return format, "PKCS#8", StatusMalformed, err.Error(), false
		}
		return format, "PKCS#8", StatusEncrypted, "encrypted PKCS#8 private key; decryption was not attempted", true
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return format, "RSA", StatusConfirmed, "", false
		}
		return format, "RSA", StatusMalformed, err.Error(), false
	case "EC PRIVATE KEY":
		_, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			return format, "EC", StatusConfirmed, "", false
		}
		return format, "EC", StatusMalformed, err.Error(), false
	case "DSA PRIVATE KEY":
		_, err := parseDSATraditionalPrivateKey(block.Bytes)
		if err == nil {
			return format, "DSA", StatusConfirmed, "", false
		}
		return format, "DSA", StatusMalformed, fmt.Sprintf("invalid DSA private key: %v", err), false
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			_, dsaErr := parseDSAPKCS8PrivateKey(block.Bytes)
			if dsaErr == nil {
				return format, "DSA/PKCS#8", StatusConfirmed, "", false
			}
			return format, "PKCS#8", StatusMalformed, fmt.Sprintf("%v; DSA parser: %v", err, dsaErr), false
		}
		switch key.(type) {
		case *rsa.PrivateKey:
			return format, "RSA/PKCS#8", StatusConfirmed, "", false
		case *ecdsa.PrivateKey:
			return format, "EC/PKCS#8", StatusConfirmed, "", false
		case ed25519.PrivateKey:
			return format, "Ed25519/PKCS#8", StatusConfirmed, "", false
		case *dsa.PrivateKey:
			return format, "DSA/PKCS#8", StatusConfirmed, "", false
		default:
			return format, "PKCS#8", StatusReview, "unsupported PKCS#8 private-key algorithm", false
		}
	default:
		return format, strings.TrimSuffix(block.Type, " PRIVATE KEY"), StatusReview, "unsupported private-key PEM type", false
	}
}

func normalizedName(candidate Candidate) string {
	return strings.ToLower(strings.TrimSpace(candidate.Name))
}

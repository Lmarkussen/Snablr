package scanner

import (
	"testing"

	"snablr/internal/credentialanalysis"
)

// ppkV3 is a format 3 PuTTY key without encryption, written from the PuTTY
// format description with a synthetic ed25519 key and a valid MAC.
const ppkV3 = "PuTTY-User-Key-File-3: ssh-ed25519\r\n" +
	"Encryption: none\r\n" +
	"Comment: deploy@build-synthetic\r\n" +
	"Public-Lines: 2\r\n" +
	"AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\r\n" +
	"BwcH\r\n" +
	"Private-Lines: 1\r\n" +
	"AAAAIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ\r\n" +
	"Private-MAC: 804da05a912da1f4019c0d8a96795483b17042037133842246ae25ba6076182c\r\n"

// An unencrypted PuTTY key with a valid MAC is a usable private key and is
// actionable; a passphrase-protected one is review material.
func TestPuTTYKeysAreClassified(t *testing.T) {
	findings, candidates := harvestAt(t, "Users/deploy/Documents/keys/deploy.ppk", ppkV3)
	if !actionableRules(findings)["keyinspect.content.private_key_header"] {
		t.Errorf("unencrypted PuTTY key is not actionable: %v", findingRuleSet(findings))
	}
	confirmedKey := false
	for _, c := range candidates {
		if c.CredentialType == "private_key" && c.Verification == credentialanalysis.Confirmed && c.KeyFormat == "PuTTY" {
			confirmedKey = true
		}
	}
	if !confirmedKey {
		t.Errorf("unencrypted PuTTY key not confirmed: %+v", candidates)
	}

	encrypted := "PuTTY-User-Key-File-3: ssh-ed25519\r\nEncryption: aes256-cbc\r\nComment: deploy@build-synthetic\r\nPublic-Lines: 2\r\nAAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\r\nBwcH\r\nKey-Derivation: Argon2id\r\nArgon2-Memory: 8192\r\nArgon2-Passes: 13\r\nArgon2-Parallelism: 1\r\nArgon2-Salt: 0123456789abcdef0123456789abcdef\r\nPrivate-Lines: 1\r\nBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF\r\nPrivate-MAC: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\r\n"
	findings, _ = harvestAt(t, "Users/deploy/Documents/keys/locked.ppk", encrypted)
	if !findingRuleSet(findings)["keyinspect.content.private_key_header"] {
		t.Errorf("encrypted PuTTY key is not reported: %v", findingRuleSet(findings))
	}
	if len(actionableRules(findings)) > 0 {
		t.Errorf("encrypted PuTTY key is actionable: %v", actionableRules(findings))
	}
}

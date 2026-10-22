package credentialanalysis

import (
	"strings"
	"testing"
)

const (
	testNTLMResponse = "11223344556677889900aabbccddeeff0011223344556677"
	testNTProof      = "00112233445566778899aabbccddeeff"
	testChallenge    = "a1b2c3d4e5f60718"
	testNTLMv2Blob   = "01010000000000000102030405060708090a0b0c0d0e0f10"
)

func TestHarvestNetNTLMRecords(t *testing.T) {
	content := "alice::SYNTHETIC:" + testNTLMResponse + ":ffeeddccbbaa99887766554433221100ffeeddccbbaa9988:" + testChallenge + "\n" +
		"bob::SYNTHETIC:" + testChallenge + ":" + testNTProof + ":" + testNTLMv2Blob + "\n"
	candidates := Harvest(HarvestInput{Content: []byte(content), Path: "captures.txt"})
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	if candidates[0].CredentialType != "netntlmv1" || candidates[0].Identity != "alice" || candidates[0].Domain != "SYNTHETIC" {
		t.Fatalf("unexpected v1 candidate: %#v", candidates[0])
	}
	if candidates[1].CredentialType != "netntlmv2" || candidates[1].Identity != "bob" || !strings.Contains(candidates[1].Value, testNTLMv2Blob) {
		t.Fatalf("unexpected v2 candidate: %#v", candidates[1])
	}
	for _, candidate := range candidates {
		if candidate.Evidence[0].Location != "line 1" && candidate.Evidence[0].Location != "line 2" {
			t.Fatalf("missing line provenance: %#v", candidate.Evidence)
		}
	}
}

func TestHarvestRejectsMalformedNetNTLMRecords(t *testing.T) {
	content := strings.Join([]string{
		"alice::SYNTHETIC:short:" + testNTLMResponse + ":" + testChallenge,
		"alice::SYNTHETIC:" + testNTLMResponse + ":not-hex:" + testChallenge,
		"alice::SYNTHETIC:" + testChallenge + ":" + testNTProof + ":not-a-blob",
		"alice::SYNTHETIC:" + testChallenge + ":" + testNTProof + ":02010000000000000102030405060708",
		"alice::SYNTHETIC:" + testChallenge + ":" + testNTProof,
		"random:0011223344556677:00112233445566778899aabbccddeeff",
	}, "\n")
	for _, candidate := range Harvest(HarvestInput{Content: []byte(content), Path: "negative.txt"}) {
		if candidate.CredentialType == "netntlmv1" || candidate.CredentialType == "netntlmv2" {
			t.Fatalf("malformed capture became credential: %#v", candidate)
		}
	}
}

func TestCredentialPresentationClassification(t *testing.T) {
	for _, credentialType := range []string{"hash", "nt_hash", "netntlmv1", "netntlmv2", "kerberos_asrep", "kerberos_tgs", "dcc", "dcc2"} {
		if got := CredentialPresentationLabel(credentialType); got != "HASH" {
			t.Errorf("%s label = %q, want HASH", credentialType, got)
		}
	}
	for _, credentialType := range []string{"password", "token", "connection_string", "api_key"} {
		if got := CredentialPresentationLabel(credentialType); got != "CREDENTIAL" {
			t.Errorf("%s label = %q, want CREDENTIAL", credentialType, got)
		}
	}
}

package credentialanalysis

import (
	"strings"
	"testing"
)

const (
	testLMHash = "aad3b435b51404eeaad3b435b51404ee"
	testNTHash = "00112233445566778899aabbccddeeff"
)

func TestHarvestCanonicalNTHashRecord(t *testing.T) {
	candidates := Harvest(HarvestInput{
		Content: []byte("comment\nSYNTHETIC\\alice:1107:" + testLMHash + ":" + testNTHash + "\n"),
		Source:  "smb",
		Host:    "synthetic-host",
		Share:   "SyntheticShare",
		Path:    "exports/pwdump.txt",
	})
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1: %#v", len(candidates), candidates)
	}
	candidate := candidates[0]
	if candidate.Verification != Confirmed || candidate.CredentialType != "nt_hash" || candidate.Value != testNTHash {
		t.Fatalf("unexpected candidate: %#v", candidate)
	}
	if candidate.Identity != "alice" || candidate.Domain != "SYNTHETIC" || candidate.RID != 1107 {
		t.Fatalf("qualified identity metadata = %#v", candidate)
	}
	if len(candidate.Evidence) != 1 || candidate.Evidence[0].Location != "line 2" || candidate.Evidence[0].Path != "exports/pwdump.txt" {
		t.Fatalf("provenance = %#v", candidate.Evidence)
	}
	if candidate.ValidationBasis != "structured_nt_hash_record" {
		t.Fatalf("validation basis = %q", candidate.ValidationBasis)
	}
}

func TestHarvestStructuredNTHashFields(t *testing.T) {
	tests := []struct {
		name, path, content, identity, domain string
	}{
		{"json", "records.json", `{"username":"alice","nt_hash":"00112233445566778899aabbccddeeff"}`, "alice", ""},
		{"yaml", "records.yaml", "username: alice\nntlm_hash: 00112233445566778899aabbccddeeff\n", "alice", ""},
		{"config", "records.ini", "[account]\nusername=alice\nnthash=00112233445566778899aabbccddeeff\n", "alice", ""},
		{"qualified", "records.json", `{"username":"alice@SYNTHETIC","nthash":"00112233445566778899aabbccddeeff"}`, "alice", "SYNTHETIC"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidates := Harvest(HarvestInput{Content: []byte(test.content), Path: test.path})
			if len(candidates) != 1 {
				t.Fatalf("candidate count = %d, want 1: %#v", len(candidates), candidates)
			}
			candidate := candidates[0]
			if candidate.CredentialType != "nt_hash" || candidate.Verification != Confirmed || candidate.Value != testNTHash {
				t.Fatalf("unexpected candidate: %#v", candidate)
			}
			if candidate.Identity != test.identity || candidate.Domain != test.domain {
				t.Fatalf("identity metadata = %#v", candidate)
			}
		})
	}
}

func TestHarvestRejectsMalformedAndUnrelatedHashRecords(t *testing.T) {
	content := strings.Join([]string{
		"alice:bad-rid:" + testLMHash + ":" + testNTHash,
		"alice:1001:31d6cfe0d16ae931b73c59d7e0c089c0:" + testNTHash,
		"alice:1001:" + testLMHash + ":not-a-hash",
		"alice:1001:" + testLMHash + ":0011223344556677",
		"alice:1001:masked:00112233445566778899aabbccddeeff",
		"PLACEHOLDER:1001:" + testLMHash + ":" + testNTHash,
		`{"nt_hash":"00112233445566778899aabbccddeeff"}`,
		`{"username":"alice","hash":"00112233445566778899aabbccddeeff"}`,
		`{"username":"alice","md5":"00112233445566778899aabbccddeeff"}`,
		`{"username":"alice","sha256":"00112233445566778899aabbccddeeff"}`,
		`{"username":"alice","guid":"00112233445566778899aabbccddeeff"}`,
		"unrelated=00112233445566778899aabbccddeeff",
	}, "\n")
	for _, candidate := range Harvest(HarvestInput{Content: []byte(content), Path: "negative.txt"}) {
		if candidate.CredentialType == "nt_hash" {
			t.Fatalf("unrelated or malformed content became NT hash: %#v", candidate)
		}
	}
}

func TestHarvestDoesNotPairIdentityAcrossStructuredObjects(t *testing.T) {
	content := `[{"username":"alice"},{"nt_hash":"00112233445566778899aabbccddeeff"}]`
	for _, candidate := range Harvest(HarvestInput{Content: []byte(content), Path: "records.json"}) {
		if candidate.CredentialType == "nt_hash" {
			t.Fatalf("identity was paired across JSON objects: %#v", candidate)
		}
	}
}

func TestAnalyzeMergesDuplicateNTHashRecords(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: []byte(
		"alice:1001:" + testLMHash + ":" + testNTHash + "\n" +
			"alice:1001:" + testLMHash + ":" + testNTHash + "\n"), Path: "records.txt"})
	report := Analyze(candidates)
	if len(report.Confirmed) != 1 {
		t.Fatalf("confirmed count = %d, want 1: %#v", len(report.Confirmed), report.Confirmed)
	}
	if report.Confirmed[0].Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", report.Confirmed[0].Occurrences)
	}
}

package credentialanalysis

import (
	"strings"
	"testing"
)

const (
	testASREP = "$krb5asrep$23$alice@SYNTHETIC:00112233445566778899aabbccddeeff$" +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testTGS = "$krb5tgs$23$*alice$SYNTHETIC$cifs/server.synthetic*$" +
		"00112233445566778899aabbccddeeff$" +
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testDCC1 = "$DCC1#alice#00112233445566778899aabbccddeeff"
	testDCC2 = "$DCC2$10240#alice#00112233445566778899aabbccddeeff"
)

func TestHarvestApprovedCaptureRecords(t *testing.T) {
	candidates := Harvest(HarvestInput{Content: []byte(strings.Join([]string{testASREP, testTGS, testDCC1, testDCC2}, "\n")), Path: "captures"})
	if len(candidates) != 4 {
		t.Fatalf("candidate count = %d, want 4: %#v", len(candidates), candidates)
	}
	want := []struct {
		typ, identity, domain, basis string
		value                        string
	}{
		{"kerberos_asrep", "alice", "SYNTHETIC", "structured_kerberos_asrep_record", testASREP},
		{"kerberos_tgs", "alice", "SYNTHETIC", "structured_kerberos_tgs_record", testTGS},
		{"dcc", "alice", "", "structured_dcc_record", testDCC1},
		{"dcc2", "alice", "", "structured_dcc2_record", testDCC2},
	}
	for index, expected := range want {
		candidate := candidates[index]
		if candidate.CredentialType != expected.typ || candidate.Identity != expected.identity || candidate.Domain != expected.domain || candidate.ValidationBasis != expected.basis || candidate.Value != expected.value || candidate.Verification != Confirmed {
			t.Fatalf("candidate %d = %#v, want type=%q identity=%q domain=%q basis=%q value=%q confirmed", index, candidate, expected.typ, expected.identity, expected.domain, expected.basis, expected.value)
		}
		if candidate.Evidence[0].Location != "line "+string(rune('1'+index)) {
			t.Fatalf("candidate %d evidence = %#v", index, candidate.Evidence)
		}
	}
}

func TestHarvestRejectsMalformedApprovedCaptureRecords(t *testing.T) {
	invalid := []string{
		"$krb5asrep$17$alice@SYNTHETIC:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff",
		"$krb5asrep$23$alice@SYNTHETIC:not-hex$00112233445566778899aabbccddeeff",
		"$krb5asrep$23$alice@SYNTHETIC:00112233445566778899aabbccddeeff$",
		"$krb5tgs$23$*alice$SYNTHETIC$cifs/server*$short$00112233445566778899aabbccddeeff",
		"$krb5tgs$23$alice$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff2233445566778899aabbccddeeff2233445566778899aabbccddeeff$00112233445566778899aabbccddeeff",
		"$DCC1#alice#not-hex",
		"$DCC2$0#alice#00112233445566778899aabbccddeeff",
		"$DCC2$1000001#alice#00112233445566778899aabbccddeeff",
		"00112233445566778899aabbccddeeff",
	}
	for _, line := range invalid {
		for _, candidate := range Harvest(HarvestInput{Content: []byte(line), Path: "negative"}) {
			switch candidate.CredentialType {
			case "kerberos_asrep", "kerberos_tgs", "dcc", "dcc2":
				t.Fatalf("invalid capture became candidate: line=%q candidate=%#v", line, candidate)
			}
		}
	}
}

func TestHarvestCaptureRecordsPreservesMultipleLinesAndProvenance(t *testing.T) {
	content := "prefix\n" + testDCC1 + "\n" + testDCC2 + "\n"
	candidates := Harvest(HarvestInput{Content: []byte(content), Source: "smb", Host: "host", Share: "share", Path: "random-name"})
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	for index, candidate := range candidates {
		if candidate.Source != "smb" || candidate.Host != "host" || candidate.Share != "share" || candidate.Path != "random-name" {
			t.Fatalf("candidate %d provenance = %#v", index, candidate)
		}
		if candidate.Evidence[0].Path != "random-name" || candidate.Evidence[0].Source != "smb" || candidate.Evidence[0].Location != "line "+string(rune('2'+index)) {
			t.Fatalf("candidate %d evidence = %#v", index, candidate.Evidence)
		}
	}
}

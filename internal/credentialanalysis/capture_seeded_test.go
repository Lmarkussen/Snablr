package credentialanalysis

import (
	"fmt"
	"math/rand"
	"testing"
)

type seededCaptureCase struct {
	value string
	typ   string
}

func TestSeededCaptureCorpusUsesIndependentGroundTruth(t *testing.T) {
	seeds := []int64{20261022, 20261023, 20261024, 20261025}
	for _, seed := range seeds {
		rng := rand.New(rand.NewSource(seed))
		account := fmt.Sprintf("user%d", rng.Intn(9000)+1000)
		cases := []seededCaptureCase{
			{fmt.Sprintf("$krb5asrep$23$%s@SYNTHETIC:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", account), "kerberos_asrep"},
			{fmt.Sprintf("$krb5tgs$23$*%s$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff", account), "kerberos_tgs"},
			{fmt.Sprintf("$DCC1#%s#00112233445566778899aabbccddeeff", account), "dcc"},
			{fmt.Sprintf("$DCC2$%d#%s#00112233445566778899aabbccddeeff", 1+rng.Intn(maxDCC2Iterations), account), "dcc2"},
		}
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			for index, expected := range cases {
				candidate := Harvest(HarvestInput{Content: []byte(expected.value), Path: fmt.Sprintf("random-%d", rng.Intn(100000))})
				if len(candidate) != 1 || candidate[0].CredentialType != expected.typ || candidate[0].Verification != Confirmed || candidate[0].Value != expected.value {
					t.Fatalf("case %d expected independent ground truth type=%q value=%q, got %#v", index, expected.typ, expected.value, candidate)
				}
			}
			negative := []string{
				"$krb5asrep$23$" + account + "@SYNTHETIC:invalid$00112233445566778899aabbccddeeff",
				"$krb5tgs$17$*" + account + "$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff",
				"$DCC2$1000001#" + account + "#00112233445566778899aabbccddeeff",
				"00112233445566778899aabbccddeeff",
			}
			for _, value := range negative {
				for _, candidate := range Harvest(HarvestInput{Content: []byte(value), Path: "negative"}) {
					if IsHashCredentialType(candidate.CredentialType) {
						t.Fatalf("negative case became hash candidate: %q -> %#v", value, candidate)
					}
				}
			}
		})
	}
}

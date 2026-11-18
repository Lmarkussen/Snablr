package credentialanalysis

import "testing"

const syntheticCiphertext = "QkFTRTY0LUNJUEhFUlRFWFQ="

// A field that names its value as encrypted, hashed or encoded must never be
// confirmed as a plaintext credential. The material is kept as encrypted
// review evidence instead.
func TestProtectedSecretFieldsAreNeverConfirmedAsPlaintext(t *testing.T) {
	cases := map[string]string{
		"credential.xml": "<credential><user>svc_synthetic</user><encryptedPassword>" + syntheticCiphertext + "</encryptedPassword></credential>",
		"service.ini":    "[svc]\nuser=svc_synthetic\nencrypted_password=" + syntheticCiphertext + "\n",
		"adjacent.txt":   "user=svc_synthetic\nencrypted_password=" + syntheticCiphertext + "\n",
		"sameline.txt":   "user=svc_synthetic enc_password=" + syntheticCiphertext + "\n",
	}
	for path, content := range cases {
		t.Run(path, func(t *testing.T) {
			candidates := Harvest(HarvestInput{Path: path, Content: []byte(content)})
			kept := false
			for _, candidate := range candidates {
				if candidate.Value != syntheticCiphertext {
					continue
				}
				if candidate.Verification == Confirmed {
					t.Fatalf("encrypted value confirmed as plaintext via %q", candidate.ValidationBasis)
				}
				if candidate.Encrypted {
					kept = true
				}
			}
			if !kept {
				t.Fatalf("encrypted material was not preserved as encrypted review evidence: %#v", candidates)
			}
		})
	}
}

func TestPlainPasswordFieldStillConfirms(t *testing.T) {
	for _, candidate := range Harvest(HarvestInput{Path: "credential.xml", Content: []byte("<credential><user>svc_synthetic</user><password>Synthetic-Plain-1!</password></credential>")}) {
		if candidate.Value == "Synthetic-Plain-1!" && candidate.Verification == Confirmed && !candidate.Encrypted {
			return
		}
	}
	t.Fatal("plain <password> element was no longer confirmed")
}

func TestProtectedSecretFieldName(t *testing.T) {
	for key, want := range map[string]bool{
		"encryptedPassword": true, "enc_password": true, "password_encrypted": true, "PasswordHash": true,
		"dpapiPassword": true, "password": false, "db_password": false, "passord": false, "encryption_note": false,
	} {
		if got := ProtectedSecretFieldName(key); got != want {
			t.Errorf("ProtectedSecretFieldName(%q) = %v, want %v", key, got, want)
		}
	}
}

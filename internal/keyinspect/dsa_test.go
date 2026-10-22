package keyinspect

import (
	"crypto/dsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestInspectorValidatesTraditionalAndPKCS8DSA(t *testing.T) {
	key := syntheticDSAKey()
	traditionalDER, err := asn1.Marshal(struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}{0, key.P, key.Q, key.G, key.Y, key.X})
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER := syntheticDSAPKCS8(t, key)

	cases := []struct {
		name    string
		content []byte
		format  string
	}{
		{"traditional", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: traditionalDER}), "PEM"},
		{"pkcs8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}), "PEM"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			matches := New().InspectContent(Candidate{Name: "arbitrary-extensionless-key"}, test.content)
			if len(matches) != 1 {
				t.Fatalf("matches = %#v", matches)
			}
			match := matches[0]
			if match.Status != StatusConfirmed || match.Format != test.format || match.Algorithm != "DSA" && match.Algorithm != "DSA/PKCS#8" {
				t.Fatalf("unexpected match = %#v", match)
			}
		})
	}
}

func TestInspectorRejectsInvalidDSAStructure(t *testing.T) {
	key := syntheticDSAKey()
	pkcs8DER := syntheticDSAPKCS8(t, key)
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"trailing", append(append([]byte(nil), pkcs8DER...), 0)},
		{"invalid-scalar", syntheticDSAPKCS8(t, &dsa.PrivateKey{PublicKey: key.PublicKey, X: big.NewInt(0)})},
		{"invalid-generator", syntheticDSAPKCS8(t, &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: key.P, Q: key.Q, G: big.NewInt(5)}}, X: key.X})},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: test.body})
			matches := New().InspectContent(Candidate{Name: "candidate"}, content)
			if len(matches) != 1 || matches[0].Status == StatusConfirmed {
				t.Fatalf("invalid DSA structure confirmed: %#v", matches)
			}
		})
	}
}

func TestInspectorRecognizesValidAndRejectsMalformedEncryptedPKCS8(t *testing.T) {
	key := syntheticDSAKey()
	params, err := asn1.Marshal(dsaPKCS8Parameters{P: key.P, Q: key.Q, G: key.G})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := asn1.Marshal(encryptedPKCS8PrivateKey{
		Algorithm:     algorithmIdentifier(t, params),
		EncryptedData: []byte{1, 2, 3, 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := New().InspectContent(Candidate{Name: "encrypted-extensionless"}, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: envelope}))
	if len(valid) != 1 || valid[0].Status != StatusEncrypted || !valid[0].Encrypted {
		t.Fatalf("valid encrypted envelope = %#v", valid)
	}
	malformed := New().InspectContent(Candidate{Name: "encrypted-extensionless"}, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}))
	if len(malformed) != 1 || malformed[0].Status == StatusEncrypted || malformed[0].Status == StatusConfirmed {
		t.Fatalf("malformed encrypted envelope accepted: %#v", malformed)
	}
}

func TestInspectorIgnoresDSANonPrivateArtifacts(t *testing.T) {
	for _, content := range [][]byte{
		[]byte("-----BEGIN DSA PUBLIC KEY-----\nsynthetic\n-----END DSA PUBLIC KEY-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nsynthetic\n-----END CERTIFICATE REQUEST-----\n"),
	} {
		if matches := New().InspectContent(Candidate{Name: "extensionless-artifact"}, content); len(matches) != 0 {
			t.Fatalf("non-private DSA artifact produced matches: %#v", matches)
		}
	}
}

func syntheticDSAKey() *dsa.PrivateKey {
	p := big.NewInt(23)
	q := big.NewInt(11)
	g := big.NewInt(4)
	x := big.NewInt(3)
	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: p, Q: q, G: g}, Y: new(big.Int).Exp(g, x, p)},
		X:         x,
	}
}

func syntheticDSAPKCS8(t *testing.T, key *dsa.PrivateKey) []byte {
	t.Helper()
	params, err := asn1.Marshal(dsaPKCS8Parameters{P: key.P, Q: key.Q, G: key.G})
	if err != nil {
		t.Fatal(err)
	}
	private, err := asn1.Marshal(key.X)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(dsaPKCS8PrivateKey{Version: 0, Algorithm: algorithmIdentifier(t, params), PrivateKey: private})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func algorithmIdentifier(t *testing.T, params []byte) pkix.AlgorithmIdentifier {
	t.Helper()
	return pkix.AlgorithmIdentifier{Algorithm: dsaAlgorithmOID, Parameters: asn1.RawValue{FullBytes: params}}
}

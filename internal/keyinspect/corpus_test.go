package keyinspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

const privateKeyCorpusSeed int64 = 20261022

type privateKeyCorpusCase struct {
	name          string
	content       []byte
	expected      string
	expectedValue bool
}

func TestSeededPrivateKeyCorpusAgainstIndependentOracle(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(privateKeyCorpusSeed))
	temporary := t.TempDir()
	valid := deterministicECPrivateKey(t)
	pkcs8 := deterministicPKCS8PrivateKey(t)
	encrypted := deterministicEncryptedPEM(t, valid)
	malformed := []byte("-----BEGIN EC PRIVATE KEY-----\nnot-base64\n-----END EC PRIVATE KEY-----\n")
	public := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly synthetic@lab\n")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("synthetic certificate")})
	cases := []privateKeyCorpusCase{
		{name: "id_ecdsa", content: valid, expected: StatusConfirmed, expectedValue: true},
		{name: "customer-pkcs8", content: pkcs8, expected: StatusConfirmed, expectedValue: true},
		{name: "encrypted-key", content: encrypted, expected: StatusEncrypted, expectedValue: true},
		{name: "customer-" + randomCorpusSuffix(rng), content: valid, expected: StatusConfirmed, expectedValue: true},
		{name: "broken-key", content: malformed, expected: StatusMalformed, expectedValue: true},
		{name: "authorized_keys", content: public, expected: "", expectedValue: false},
		{name: "certificate.crt", content: certificate, expected: "", expectedValue: false},
		{name: "notes", content: []byte("private key mentioned in documentation"), expected: "", expectedValue: false},
	}

	for _, testCase := range cases {
		path := filepath.Join(temporary, testCase.name)
		if err := os.WriteFile(path, testCase.content, 0o600); err != nil {
			t.Fatal(err)
		}
		independent := independentPEMStatus(testCase.content)
		if independent != testCase.expected {
			t.Fatalf("manifest oracle mismatch for %s: got %q want %q", testCase.name, independent, testCase.expected)
		}
		original := append([]byte{}, testCase.content...)
		matches := New().InspectContent(Candidate{Name: testCase.name}, testCase.content)
		if testCase.expected == "" {
			if len(matches) != 0 {
				t.Fatalf("negative corpus case %s produced %#v", testCase.name, matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].Status != testCase.expected {
			t.Fatalf("corpus case %s produced %#v, want %s", testCase.name, matches, testCase.expected)
		}
		if testCase.expectedValue && !bytes.Equal(testCase.content, original) {
			t.Fatal("corpus evidence changed")
		}
	}
}

func deterministicPKCS8PrivateKey(t *testing.T) []byte {
	t.Helper()
	curve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: big.NewInt(2)}
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func deterministicEncryptedPEM(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(plaintext)
	if block == nil {
		t.Fatal("failed to decode deterministic key")
	}
	keyBlock, err := x509.EncryptPEMBlock(&seededReader{rng: rand.New(rand.NewSource(privateKeyCorpusSeed + 1))}, block.Type, block.Bytes, []byte("synthetic-passphrase"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(keyBlock)
}

type seededReader struct{ rng *rand.Rand }

func (r *seededReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(r.rng.Intn(256))
	}
	return len(buffer), nil
}

func deterministicECPrivateKey(t *testing.T) []byte {
	t.Helper()
	curve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: big.NewInt(1)}
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func independentPEMStatus(content []byte) string {
	block, _ := pem.Decode(content)
	if block == nil {
		if bytes.Contains(content, []byte("PRIVATE KEY")) {
			return StatusMalformed
		}
		return ""
	}
	if x509.IsEncryptedPEMBlock(block) {
		return StatusEncrypted
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return StatusConfirmed
		}
		return StatusMalformed
	case "PRIVATE KEY":
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return StatusConfirmed
		}
		return StatusMalformed
	default:
		return ""
	}
}

func randomCorpusSuffix(rng *rand.Rand) string {
	return string([]byte{'a' + byte(rng.Intn(26)), 'a' + byte(rng.Intn(26)), 'a' + byte(rng.Intn(26))})
}

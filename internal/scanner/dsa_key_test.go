package scanner

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestDSAPKCS8CandidatePreservesEvidenceAndMetadata(t *testing.T) {
	p, q, g, x := big.NewInt(23), big.NewInt(11), big.NewInt(4), big.NewInt(3)
	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{p, q, g})
	if err != nil {
		t.Fatal(err)
	}
	private, err := asn1.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, Parameters: asn1.RawValue{FullBytes: params}}, private})
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)
	evaluation := engine.Evaluate(FileMetadata{FilePath: "Exports/arbitrary-extensionless", Name: "arbitrary-extensionless", Size: int64(len(content))}, content)
	if len(evaluation.Findings) != 1 || len(sink.candidates) != 1 {
		t.Fatalf("expected one finding and candidate, findings=%#v candidates=%#v", evaluation.Findings, sink.candidates)
	}
	candidate := sink.candidates[0]
	if candidate.Verification != credentialanalysis.Confirmed || candidate.KeyAlgorithm != "DSA/PKCS#8" || candidate.KeyStatus != "confirmed" || candidate.Value != string(content) || candidate.Path != "Exports/arbitrary-extensionless" {
		t.Fatalf("unexpected DSA candidate: %#v", candidate)
	}
}

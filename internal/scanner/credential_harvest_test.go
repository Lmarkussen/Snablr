package scanner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestEngineHarvestsOpenSSHAndMalformedPrivateKeys(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	collector := &recordingCandidateSink{}
	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	engine.SetCredentialCandidateSink(collector)
	if evaluation := engine.EvaluateContext(context.Background(), FileMetadata{FilePath: "id_ed25519", Name: "id_ed25519", Size: 1024}, pem.EncodeToMemory(valid)); evaluation.Skipped {
		t.Fatal("key unexpectedly skipped")
	}
	if len(collector.candidates) != 1 || collector.candidates[0].Verification != credentialanalysis.Confirmed {
		t.Fatalf("unexpected candidates: %#v", collector.candidates)
	}
}

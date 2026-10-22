package scanner

import (
	"archive/zip"
	"bytes"
	"testing"

	"snablr/internal/credentialanalysis"
	"snablr/internal/rules"
	"snablr/pkg/logx"
)

func TestCaptureCandidatesTraverseScannerPipelineForExtensionlessFiles(t *testing.T) {
	content := []byte("$krb5asrep$23$alice@SYNTHETIC:00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff\n" +
		"$DCC2$10240#alice#00112233445566778899aabbccddeeff\n")
	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)
	meta := FileMetadata{Source: "smb", Host: "host", Share: "share", FilePath: "arbitrary", Name: "arbitrary", Size: int64(len(content))}
	if !engine.NeedsContent(meta) {
		t.Fatal("extensionless capture file was not content-eligible")
	}
	engine.Evaluate(meta, content)
	if len(sink.candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(sink.candidates), sink.candidates)
	}
	for _, candidate := range sink.candidates {
		if candidate.Verification != credentialanalysis.Confirmed || candidate.Source != "smb" || candidate.Host != "host" || candidate.Share != "share" || candidate.Path != "arbitrary" {
			t.Fatalf("candidate lost pipeline metadata: %#v", candidate)
		}
	}
}

func TestCaptureCandidatesTraverseSupportedZIPMembers(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("nested/random-member")
	if err != nil {
		t.Fatal(err)
	}
	const value = "$krb5tgs$23$*alice$SYNTHETIC$cifs/server*$00112233445566778899aabbccddeeff$00112233445566778899aabbccddeeff"
	if _, err := entry.Write([]byte(value)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine(Options{}, &rules.Manager{}, nil, logx.New("error"))
	sink := &collectingCandidateSink{}
	engine.SetCredentialCandidateSink(sink)
	engine.Evaluate(FileMetadata{Source: "smb", Host: "host", Share: "share", FilePath: "captures.zip", Name: "captures.zip", Extension: ".zip", Size: int64(archive.Len())}, archive.Bytes())
	if len(sink.candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1: %#v", len(sink.candidates), sink.candidates)
	}
	candidate := sink.candidates[0]
	if candidate.Value != value || candidate.Container != "captures.zip" || candidate.Path != "captures.zip!nested/random-member" {
		t.Fatalf("ZIP candidate lost evidence/provenance: %#v", candidate)
	}
}

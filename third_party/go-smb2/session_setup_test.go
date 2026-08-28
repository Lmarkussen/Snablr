package smb2

import (
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"testing"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

type sessionSetupTestMechanism struct {
	complete bool
	key      []byte
}

func (m *sessionSetupTestMechanism) OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 2, 3}
}

func (m *sessionSetupTestMechanism) InitSecContext([]byte) ([]byte, bool, error) {
	return nil, m.complete, nil
}

func (m *sessionSetupTestMechanism) MechListMIC([]byte) ([]byte, error) {
	return nil, nil
}

func (m *sessionSetupTestMechanism) SessionKey() ([]byte, error) {
	return append([]byte(nil), m.key...), nil
}

func TestSessionSetupActionTransitions(t *testing.T) {
	tests := []struct {
		name          string
		status        NtStatus
		tokenPresent  bool
		mechanismDone bool
		want          sessionSetupAction
		wantErr       bool
	}{
		{
			name:          "more processing continues",
			status:        STATUS_MORE_PROCESSING_REQUIRED,
			tokenPresent:  true,
			mechanismDone: false,
			want:          sessionSetupContinue,
		},
		{
			name:          "more processing sends final request",
			status:        STATUS_MORE_PROCESSING_REQUIRED,
			tokenPresent:  true,
			mechanismDone: true,
			want:          sessionSetupSendFinal,
		},
		{
			name:          "success with final token completes",
			status:        STATUS_SUCCESS,
			tokenPresent:  true,
			mechanismDone: true,
			want:          sessionSetupComplete,
		},
		{
			name:          "success with empty token and complete mechanism",
			status:        STATUS_SUCCESS,
			tokenPresent:  false,
			mechanismDone: true,
			want:          sessionSetupComplete,
		},
		{
			name:          "success with empty token rejects incomplete mechanism",
			status:        STATUS_SUCCESS,
			tokenPresent:  false,
			mechanismDone: false,
			wantErr:       true,
		},
		{
			name:         "more processing requires a token",
			status:       STATUS_MORE_PROCESSING_REQUIRED,
			tokenPresent: false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decideSessionSetup(tt.status, tt.tokenPresent, tt.mechanismDone)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error: %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("action = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpnegoRetainsInitialCompletion(t *testing.T) {
	client := newSpnegoClient([]Initiator{&sessionSetupTestMechanism{complete: true, key: []byte("session-key")}})
	if _, complete, err := client.initSecContext(); err != nil || !complete {
		t.Fatalf("initSecContext = complete %v, error %v", complete, err)
	}
	if !client.isComplete() {
		t.Fatal("SPNEGO discarded initial mechanism completion")
	}
}

func TestSessionSetupTerminalPreauthDoesNotHashResponse(t *testing.T) {
	s := &session{
		conn: &conn{
			dialect:                SMB311,
			preauthIntegrityHashId: SHA512,
		},
	}
	request := []byte("session setup request")
	response := []byte("terminal response")
	if err := s.updateSessionSetupPreauth(request, response, STATUS_SUCCESS); err != nil {
		t.Fatal(err)
	}
	want := sha512.Sum512(append(make([]byte, 64), request...))
	if s.preauthIntegrityHashValue != want {
		t.Fatal("terminal SESSION_SETUP response was included in preauth hash")
	}
}

func TestSessionSetupInterimPreauthHashesRequestAndResponse(t *testing.T) {
	s := &session{
		conn: &conn{
			dialect:                SMB311,
			preauthIntegrityHashId: SHA512,
		},
	}
	request := []byte("interim request")
	response := []byte("interim response")
	if err := s.updateSessionSetupPreauth(request, response, STATUS_MORE_PROCESSING_REQUIRED); err != nil {
		t.Fatal(err)
	}
	first := sha512.Sum512(append(make([]byte, 64), request...))
	want := sha512.Sum512(append(first[:], response...))
	if s.preauthIntegrityHashValue != want {
		t.Fatal("interim SESSION_SETUP transcript was not hashed exactly once")
	}
}

func TestPrepareFinalSessionSetupInstallsVerifierBeforeSessionUse(t *testing.T) {
	mechanism := &sessionSetupTestMechanism{complete: true, key: []byte("0123456789abcdef")}
	spnego := newSpnegoClient([]Initiator{mechanism})
	if _, _, err := spnego.initSecContext(); err != nil {
		t.Fatal(err)
	}
	s := &session{conn: &conn{dialect: SMB202}}
	if err := s.prepareFinalSessionSetup([]byte("final request"), spnego); err != nil {
		t.Fatal(err)
	}
	if s.verifier == nil {
		t.Fatal("final response verifier was not installed")
	}
	if !s.useSession() {
		t.Fatal("session receiver processing was not enabled after verifier setup")
	}
}

func TestPreparedSessionVerifiesSignedSessionSetupResponse(t *testing.T) {
	mechanism := &sessionSetupTestMechanism{complete: true, key: []byte("0123456789abcdef")}
	spnego := newSpnegoClient([]Initiator{mechanism})
	if _, _, err := spnego.initSecContext(); err != nil {
		t.Fatal(err)
	}
	s := &session{conn: &conn{dialect: SMB202}}
	if err := s.prepareFinalSessionSetup([]byte("final request"), spnego); err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, 64)
	copy(pkt[:4], []byte(MAGIC))
	binary.LittleEndian.PutUint16(pkt[12:14], SMB2_SESSION_SETUP)
	binary.LittleEndian.PutUint32(pkt[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	s.sign(pkt)
	if err := s.verifySessionSetupResponse(pkt); err != nil {
		t.Fatalf("valid signed response rejected: %v", err)
	}
	pkt[48] ^= 0xff
	if err := s.verifySessionSetupResponse(pkt); err == nil {
		t.Fatal("tampered signed response accepted")
	}
}

func TestSMBSessionKeyUsesFirst16Bytes(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	got, err := smbSessionKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key[:16]) {
		t.Fatalf("SMB session key = %q, want first 16 bytes", got)
	}
}

func TestSessionSetupContinuationLimitIsBounded(t *testing.T) {
	if sessionSetupMaxRounds != 8 {
		t.Fatalf("continuation limit = %d, want 8", sessionSetupMaxRounds)
	}
}

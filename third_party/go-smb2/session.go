package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/hirochachacha/go-smb2/internal/crypto/ccm"
	"github.com/hirochachacha/go-smb2/internal/crypto/cmac"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})

	outputToken, _, err := spnego.initSecContext()
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req := &SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    outputToken,
		PreviousSessionId: 0,
	}
	if conn.requireSigning {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}
	req.CreditCharge = 1
	req.CreditRequestResponse = conn.account.initRequest()

	var s *session
	for round := 0; round < sessionSetupMaxRounds; round++ {
		var rr *requestResponse
		if s == nil {
			rr, err = conn.send(req, ctx)
		} else {
			rr, err = s.send(req, ctx)
		}
		if err != nil {
			return nil, err
		}

		var pkt []byte
		if s == nil {
			pkt, err = conn.recv(rr)
		} else {
			pkt, err = s.recv(rr)
		}
		if err != nil {
			return nil, err
		}

		p := PacketCodec(pkt)
		status := NtStatus(p.Status())
		if status != STATUS_MORE_PROCESSING_REQUIRED && status != STATUS_SUCCESS {
			return nil, &InvalidResponseError{fmt.Sprintf("unexpected session setup status: %v", status)}
		}

		res, err := accept(SMB2_SESSION_SETUP, pkt)
		if err != nil {
			return nil, err
		}
		r := SessionSetupResponseDecoder(res)
		if r.IsInvalid() {
			return nil, &InvalidResponseError{"broken session setup response format"}
		}

		if s == nil {
			sessionFlags := r.SessionFlags()
			if conn.requireSigning {
				if sessionFlags&SMB2_SESSION_FLAG_IS_GUEST != 0 {
					return nil, &InvalidResponseError{"guest account doesn't support signing"}
				}
				if sessionFlags&SMB2_SESSION_FLAG_IS_NULL != 0 {
					return nil, &InvalidResponseError{"anonymous account doesn't support signing"}
				}
			}
			s = &session{
				conn:           conn,
				treeConnTables: make(map[uint32]*treeConn),
				sessionFlags:   sessionFlags,
				sessionId:      p.SessionId(),
			}
			if conn.dialect == SMB311 {
				s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue
			}
			// This is needed only so continuation requests carry the session ID.
			conn.session = s
		}
		if p.SessionId() != s.sessionId {
			return nil, &InvalidResponseError{"session id changed during session setup"}
		}

		// Every SESSION_SETUP request belongs in the SMB 3.1.1 preauth state.
		// An interim response belongs there too; a terminal response does not
		// participate in deriving the key used to verify that response.
		if err := s.updateSessionSetupPreauth(rr.pkt, pkt, status); err != nil {
			return nil, err
		}

		if status == STATUS_SUCCESS {
			var complete bool
			if token := r.SecurityBuffer(); len(token) != 0 {
				_, complete, err = spnego.acceptSecContext(token)
				if err != nil {
					return nil, &InvalidResponseError{err.Error()}
				}
			} else {
				// A successful response can legitimately have no security token.
				// Do not manufacture a zero-length mechanism input: nil is the
				// initial call, while an empty response means no token exists.
				complete = spnego.isComplete()
			}
			if _, err := decideSessionSetup(status, len(r.SecurityBuffer()) != 0, complete); err != nil {
				return nil, err
			}
			if err := s.installSecurity(spnego); err != nil {
				return nil, err
			}
			// The first terminal response arrives before receiver-side session
			// processing can be enabled because its session ID was unknown. It
			// is nevertheless verified before the response is accepted.
			if err := s.verifySessionSetupResponse(pkt); err != nil {
				return nil, err
			}
			s.sessionFlags = r.SessionFlags()
			s.enableSession()
			return s, nil
		}

		if len(r.SecurityBuffer()) == 0 {
			return nil, &InvalidResponseError{"session setup continuation has no security token"}
		}
		outputToken, complete, err := spnego.acceptSecContext(r.SecurityBuffer())
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}
		}
		req.SecurityBuffer = outputToken
		req.CreditRequestResponse = 0

		action, err := decideSessionSetup(status, true, complete)
		if err != nil {
			return nil, err
		}
		if action == sessionSetupContinue {
			continue
		}

		// The completed mechanism's key is reduced to the 16-byte SMB
		// Session.SessionKey before SMB 3.1.1 signing-key derivation.
		rr, err = s.send(req, ctx)
		if err != nil {
			return nil, err
		}
		if err := s.prepareFinalSessionSetup(rr.pkt, spnego); err != nil {
			return nil, err
		}

		// The final SESSION_SETUP response is signed. The preparation helper
		// installs the verifier and enables receiver-side session processing
		// before this receive.
		pkt, err = s.recv(rr)
		if err != nil {
			return nil, err
		}
		res, err = accept(SMB2_SESSION_SETUP, pkt)
		if err != nil {
			return nil, err
		}
		r = SessionSetupResponseDecoder(res)
		if r.IsInvalid() || NtStatus(PacketCodec(pkt).Status()) != STATUS_SUCCESS {
			return nil, &InvalidResponseError{"broken session setup response format"}
		}
		s.sessionFlags = r.SessionFlags()
		return s, nil
	}
	return nil, &InvalidResponseError{"SMB session setup exceeded continuation limit"}
}

const sessionSetupMaxRounds = 8

type sessionSetupAction uint8

const (
	sessionSetupContinue sessionSetupAction = iota
	sessionSetupSendFinal
	sessionSetupComplete
)

// sessionSetupAction is the mechanism-agnostic terminal-state rule for the
// SMB SESSION_SETUP exchange. The caller supplies completion after consuming
// a present mechanism token, or the mechanism's existing completion state
// when the terminal response has no token.
func decideSessionSetup(status NtStatus, tokenPresent, mechanismComplete bool) (sessionSetupAction, error) {
	switch status {
	case STATUS_MORE_PROCESSING_REQUIRED:
		if !tokenPresent {
			return sessionSetupContinue, &InvalidResponseError{"session setup continuation has no security token"}
		}
		if mechanismComplete {
			return sessionSetupSendFinal, nil
		}
		return sessionSetupContinue, nil
	case STATUS_SUCCESS:
		if !mechanismComplete {
			return sessionSetupComplete, &InvalidResponseError{"SMB session setup succeeded before the authentication mechanism completed"}
		}
		return sessionSetupComplete, nil
	default:
		return sessionSetupComplete, &InvalidResponseError{fmt.Sprintf("unexpected session setup status: %v", status)}
	}
}

type session struct {
	*conn
	treeConnTables            map[uint32]*treeConn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	signer    hash.Hash
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) updatePreauth(pkt []byte) error {
	if s.conn.dialect != SMB311 {
		return nil
	}
	switch s.conn.preauthIntegrityHashId {
	case SHA512:
		h := sha512.New()
		_, _ = h.Write(s.preauthIntegrityHashValue[:])
		_, _ = h.Write(pkt)
		h.Sum(s.preauthIntegrityHashValue[:0])
		return nil
	default:
		return &InvalidResponseError{"unknown preauth integrity hash algorithm"}
	}
}

func (s *session) updateSessionSetupPreauth(request, response []byte, status NtStatus) error {
	if err := s.updatePreauth(request); err != nil {
		return err
	}
	if status == STATUS_MORE_PROCESSING_REQUIRED {
		return s.updatePreauth(response)
	}
	return nil
}

func (s *session) prepareFinalSessionSetup(request []byte, spnego *spnegoClient) error {
	if err := s.updatePreauth(request); err != nil {
		return err
	}
	if err := s.installSecurity(spnego); err != nil {
		return err
	}
	// The final SESSION_SETUP response is signed. Install the verifier and
	// enable receiver-side session processing before receiving that packet.
	s.enableSession()
	return nil
}

func smbSessionKey(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, &InvalidResponseError{"authentication mechanism returned no session key"}
	}
	result := make([]byte, 16)
	copy(result, key)
	return result, nil
}

func (s *session) installSecurity(spnego *spnegoClient) error {
	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) != 0 {
		return nil
	}

	mechanismKey, err := spnego.sessionKey()
	if err != nil {
		return &InternalError{err.Error()}
	}
	sessionKey, err := smbSessionKey(mechanismKey)
	if err != nil {
		return err
	}

	switch s.conn.dialect {
	case SMB202, SMB210:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)
	case SMB300, SMB302:
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)
		s.verifier = cmac.New(ciph)

		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

		ciph, err = aes.NewCipher(encryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}

		ciph, err = aes.NewCipher(decryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}
	case SMB311:
		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)
		s.verifier = cmac.New(ciph)

		encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
		decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

		switch s.cipherId {
		case AES128CCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}
		case AES128GCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}
		}
	}
	return nil
}

func (s *session) logoff(ctx context.Context) error {
	req := new(LogoffRequest)

	req.CreditCharge = 1

	_, err := s.sendRecv(SMB2_LOGOFF, req, ctx)
	if err != nil {
		return err
	}

	s.conn.rdone <- struct{}{}
	s.conn.t.Close()

	return nil
}

func (s *session) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *session) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	if sessionId := PacketCodec(pkt).SessionId(); sessionId != s.sessionId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return pkt, err
}

func (s *session) sign(pkt []byte) []byte {
	p := PacketCodec(pkt)

	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)

	h := s.signer

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	h := s.verifier

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return bytes.Equal(signature, p.Signature())
}

func (s *session) verifySessionSetupResponse(pkt []byte) error {
	p := PacketCodec(pkt)
	if p.Flags()&SMB2_FLAGS_SIGNED == 0 {
		if s.conn.requireSigning && s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
			return &InvalidResponseError{"signing required"}
		}
		return nil
	}
	if s.verifier == nil || !s.verify(pkt) {
		return &InvalidResponseError{"unverified packet returned"}
	}
	return nil
}

func (s *session) encrypt(pkt []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 52+len(pkt)+16)

	t := TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(Encrypted)
	t.SetSessionId(s.sessionId)

	s.encrypter.Seal(c[:52], nonce, pkt, t.AssociatedData())

	t.SetSignature(c[len(c)-16:])

	c = c[:len(c)-16]

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := TransformCodec(pkt)

	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}

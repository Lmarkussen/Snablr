package smb2

import (
	"encoding/asn1"
	"fmt"

	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/spnego"
)

// Mechanism is the public authentication-mechanism contract used by the
// SMB session setup code. It intentionally exposes only the token and key
// operations needed by SPNEGO and SMB signing.
type Mechanism interface {
	// OID identifies the authentication mechanism for SPNEGO negotiation.
	OID() asn1.ObjectIdentifier
	// InitSecContext advances the mechanism. A nil input starts the context;
	// subsequent inputs are server tokens. complete reports whether the
	// mechanism has completed after processing input.
	InitSecContext(input []byte) (output []byte, complete bool, err error)
	// MechListMIC returns the mechanism MIC over the DER-encoded SPNEGO
	// mechanism list after the context is established.
	MechListMIC(mechListDER []byte) ([]byte, error)
	// SessionKey returns the completed mechanism key used by SMB session setup.
	// It returns an error until the mechanism has established a key.
	SessionKey() ([]byte, error)
}

// Initiator is retained as the public name used by existing callers.
type Initiator = Mechanism

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	ntlm   *ntlm.Client
	seqNum uint32
}

func (i *NTLMInitiator) OID() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMInitiator) InitSecContext(input []byte) ([]byte, bool, error) {
	if input == nil {
		i.ntlm = &ntlm.Client{
			User:        i.User,
			Password:    i.Password,
			Hash:        i.Hash,
			Domain:      i.Domain,
			Workstation: i.Workstation,
			TargetSPN:   i.TargetSPN,
		}
		nmsg, err := i.ntlm.Negotiate()
		if err != nil {
			return nil, false, err
		}
		return nmsg, false, nil
	}
	if i.ntlm == nil {
		return nil, false, fmt.Errorf("NTLM context is not initialized")
	}
	amsg, err := i.ntlm.Authenticate(input)
	if err != nil {
		return nil, false, err
	}
	return amsg, true, nil
}

func (i *NTLMInitiator) MechListMIC(bs []byte) ([]byte, error) {
	if i.ntlm == nil {
		return nil, fmt.Errorf("NTLM context is not initialized")
	}
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic, nil
}

func (i *NTLMInitiator) SessionKey() ([]byte, error) {
	if i.ntlm == nil {
		return nil, fmt.Errorf("NTLM context is not initialized")
	}
	return append([]byte(nil), i.ntlm.Session().SessionKey()...), nil
}

func (i *NTLMInitiator) infoMap() *ntlm.InfoMap {
	return i.ntlm.Session().InfoMap()
}

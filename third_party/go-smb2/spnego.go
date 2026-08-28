package smb2

import (
	"encoding/asn1"
	"fmt"

	"github.com/hirochachacha/go-smb2/internal/spnego"
)

type spnegoClient struct {
	mechs        []Initiator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Initiator
	complete     bool
}

func newSpnegoClient(mechs []Initiator) *spnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.OID()
	}
	return &spnegoClient{
		mechs:     mechs,
		mechTypes: mechTypes,
	}
}

func (c *spnegoClient) oid() asn1.ObjectIdentifier {
	return spnego.SpnegoOid
}

func (c *spnegoClient) initSecContext() (negTokenInitBytes []byte, complete bool, err error) {
	if len(c.mechs) == 0 {
		return nil, false, fmt.Errorf("SPNEGO has no mechanisms")
	}
	c.selectedMech = c.mechs[0]
	mechToken, complete, err := c.selectedMech.InitSecContext(nil)
	if err != nil {
		return nil, false, err
	}
	c.complete = complete
	negTokenInitBytes, err = spnego.EncodeNegTokenInit(c.mechTypes, mechToken)
	if err != nil {
		return nil, false, err
	}
	return negTokenInitBytes, complete, nil
}

func (c *spnegoClient) acceptSecContext(negTokenRespBytes []byte) (negTokenRespBytes1 []byte, complete bool, err error) {
	negTokenResp, err := spnego.DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return nil, false, err
	}

	if c.selectedMech == nil {
		for i, mechType := range c.mechTypes {
			if mechType.Equal(negTokenResp.SupportedMech) {
				c.selectedMech = c.mechs[i]
				break
			}
		}
	}
	if c.selectedMech == nil {
		return nil, false, fmt.Errorf("SPNEGO selected mechanism is not supported")
	}

	responseToken, complete, err := c.selectedMech.InitSecContext(negTokenResp.ResponseToken)
	if err != nil {
		return nil, false, err
	}
	c.complete = complete

	ms, err := asn1.Marshal(c.mechTypes)
	if err != nil {
		return nil, false, err
	}

	mechListMIC, err := c.selectedMech.MechListMIC(ms)
	if err != nil {
		return nil, false, err
	}

	negTokenRespBytes1, err = spnego.EncodeNegTokenResp(1, nil, responseToken, mechListMIC)
	if err != nil {
		return nil, false, err
	}

	return negTokenRespBytes1, complete, nil
}

func (c *spnegoClient) sessionKey() ([]byte, error) {
	if c.selectedMech == nil {
		return nil, fmt.Errorf("SPNEGO has no selected mechanism")
	}
	return c.selectedMech.SessionKey()
}

func (c *spnegoClient) isComplete() bool {
	return c.complete
}

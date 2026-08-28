// Package smbkerberos provides the FILE-ccache Kerberos mechanism used by
// SMB session setup. It deliberately contains no SMB transport or scanner
// policy; go-smb2 owns SPNEGO framing and SMB key derivation.
package smbkerberos

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
	"github.com/hirochachacha/go-smb2"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krbgssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/types"
)

var (
	ErrMissingCCache = errors.New("kerberos ccache unavailable")
	ErrMissingSPN    = errors.New("kerberos SMB service principal unavailable")
)

// Mechanism is a single-use Kerberos GSS mechanism for one SMB connection.
type Mechanism struct {
	client *ldapgssapi.Client
	spn    string
	key    types.EncryptionKey
}

var _ smb2.Mechanism = (*Mechanism)(nil)

// ResolveCCache resolves an explicit FILE cache or KRB5CCNAME.
func ResolveCCache(override string) (string, error) {
	value := strings.TrimSpace(override)
	if value == "" {
		value = strings.TrimSpace(os.Getenv("KRB5CCNAME"))
	}
	if value == "" {
		return "", ErrMissingCCache
	}
	if strings.HasPrefix(value, "FILE:") {
		value = strings.TrimPrefix(value, "FILE:")
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("unsupported kerberos credential cache type; use a FILE ccache")
	}
	return value, nil
}

// ResolveConfig resolves KRB5_CONFIG, falling back to the conventional path.
func ResolveConfig() string {
	if value := strings.TrimSpace(os.Getenv("KRB5_CONFIG")); value != "" {
		return value
	}
	return "/etc/krb5.conf"
}

// ValidateCCache checks that a FILE cache has at least one currently usable
// ticket without exposing cache contents.
func ValidateCCache(path string) error {
	ccache, err := loadCCache(path)
	if err != nil {
		return fmt.Errorf("unable to load kerberos ccache: %w", err)
	}
	now := time.Now().UTC()
	for _, entry := range ccache.GetEntries() {
		if entry == nil || (!entry.StartTime.IsZero() && now.Before(entry.StartTime)) {
			continue
		}
		if entry.EndTime.IsZero() || now.Before(entry.EndTime) {
			return nil
		}
	}
	return fmt.Errorf("kerberos ccache contains no valid unexpired tickets")
}

func loadCCache(path string) (ccache *credentials.CCache, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ccache = nil
			err = errors.New("malformed kerberos ccache")
		}
	}()
	return credentials.LoadCCache(path)
}

// NewFromCCache creates a mechanism targeting an SMB CIFS SPN.
func NewFromCCache(ccachePath, krb5Config, spn string) (*Mechanism, error) {
	if strings.TrimSpace(spn) == "" {
		return nil, ErrMissingSPN
	}
	if err := ValidateCCache(ccachePath); err != nil {
		return nil, err
	}
	client, err := ldapgssapi.NewClientFromCCache(ccachePath, krb5Config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize kerberos client: %w", err)
	}
	return &Mechanism{client: client, spn: spn}, nil
}

// OID identifies the standard Kerberos V5 GSS mechanism.
func (m *Mechanism) OID() asn1.ObjectIdentifier {
	// gokrb5 uses its fork-compatible ASN.1 package; copy only the OID arcs
	// into the standard type required by go-smb2's public API.
	oid := krbgssapi.OIDKRB5.OID()
	result := make(asn1.ObjectIdentifier, len(oid))
	copy(result, oid)
	return result
}

// InitSecContext creates the AP-REQ or processes the server AP-REP.
func (m *Mechanism) InitSecContext(input []byte) ([]byte, bool, error) {
	if m == nil || m.client == nil {
		return nil, false, errors.New("kerberos mechanism is not initialized")
	}
	output, continueNeeded, err := m.client.InitSecContext(m.spn, input)
	if err != nil {
		return nil, false, fmt.Errorf("kerberos SMB security context: %w", err)
	}
	if input == nil {
		_, m.key, err = m.client.Client.GetServiceTicket(m.spn)
		if err != nil {
			return nil, false, fmt.Errorf("unable to obtain CIFS service ticket: %w", err)
		}
	}
	complete := !continueNeeded
	if complete && len(m.client.Subkey.KeyValue) != 0 {
		m.key = m.client.Subkey
	}
	return output, complete, nil
}

// MechListMIC creates the complete Kerberos GSS MIC token for SPNEGO's
// mechanism list.
func (m *Mechanism) MechListMIC(payload []byte) ([]byte, error) {
	key := m.effectiveKey()
	if len(key.KeyValue) == 0 {
		return nil, errors.New("kerberos mechanism has no established session key")
	}
	token, err := krbgssapi.NewInitiatorMICToken(payload, key)
	if err != nil {
		return nil, fmt.Errorf("create kerberos mechanism MIC: %w", err)
	}
	return token.Marshal()
}

// SessionKey returns a defensive copy of the effective GSS context key.
func (m *Mechanism) SessionKey() ([]byte, error) {
	key := m.effectiveKey()
	if len(key.KeyValue) == 0 {
		return nil, errors.New("kerberos mechanism has no established session key")
	}
	return append([]byte(nil), key.KeyValue...), nil
}

func (m *Mechanism) effectiveKey() types.EncryptionKey {
	return m.key
}

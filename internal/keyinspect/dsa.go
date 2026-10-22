package keyinspect

import (
	"crypto/dsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

var dsaAlgorithmOID = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

type dsaPKCS8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

type dsaPKCS8Parameters struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

type encryptedPKCS8PrivateKey struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

func parseDSATraditionalPrivateKey(der []byte) (*dsa.PrivateKey, error) {
	key, err := ssh.ParseDSAPrivateKey(der)
	if err != nil {
		return nil, err
	}
	if err := validateDSAPrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func parseDSAPKCS8PrivateKey(der []byte) (*dsa.PrivateKey, error) {
	var info dsaPKCS8PrivateKey
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, fmt.Errorf("invalid DSA PKCS#8 structure: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid DSA PKCS#8 structure: trailing data")
	}
	if info.Version != 0 {
		return nil, fmt.Errorf("invalid DSA PKCS#8 version %d", info.Version)
	}
	if !info.Algorithm.Algorithm.Equal(dsaAlgorithmOID) {
		return nil, errors.New("PKCS#8 algorithm is not DSA")
	}
	var params dsaPKCS8Parameters
	rest, err = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid DSA PKCS#8 parameters")
	}
	var x *big.Int
	rest, err = asn1.Unmarshal(info.PrivateKey, &x)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid DSA PKCS#8 private scalar")
	}
	key := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: params.P, Q: params.Q, G: params.G}},
		X:         x,
	}
	key.Y = new(big.Int).Exp(key.G, key.X, key.P)
	if err := validateDSAPrivateKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

func parseEncryptedPKCS8(der []byte) error {
	var envelope encryptedPKCS8PrivateKey
	rest, err := asn1.Unmarshal(der, &envelope)
	if err != nil {
		return fmt.Errorf("invalid encrypted PKCS#8 envelope: %w", err)
	}
	if len(rest) != 0 || len(envelope.EncryptedData) == 0 || len(envelope.Algorithm.Algorithm) == 0 {
		return errors.New("invalid encrypted PKCS#8 envelope")
	}
	return nil
}

func validateDSAPrivateKey(key *dsa.PrivateKey) error {
	if key == nil || key.P == nil || key.Q == nil || key.G == nil || key.X == nil || key.Y == nil {
		return errors.New("missing DSA key component")
	}
	one := big.NewInt(1)
	if key.P.Cmp(one) <= 0 || key.Q.Cmp(one) <= 0 || key.G.Cmp(one) <= 0 || key.G.Cmp(key.P) >= 0 {
		return errors.New("invalid DSA parameter bounds")
	}
	if key.X.Cmp(one) < 0 || key.X.Cmp(key.Q) >= 0 {
		return errors.New("invalid DSA private scalar")
	}
	if !key.P.ProbablyPrime(64) || !key.Q.ProbablyPrime(64) {
		return errors.New("DSA parameters are not prime")
	}
	pmone := new(big.Int).Sub(new(big.Int).Set(key.P), one)
	if new(big.Int).Mod(pmone, key.Q).Sign() != 0 {
		return errors.New("DSA q does not divide p-1")
	}
	if new(big.Int).Exp(key.G, key.Q, key.P).Cmp(one) != 0 {
		return errors.New("invalid DSA generator")
	}
	if new(big.Int).Exp(key.G, key.X, key.P).Cmp(key.Y) != 0 {
		return errors.New("DSA public and private values do not match")
	}
	return nil
}

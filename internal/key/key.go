package key

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/tuanta7/keys/internal/config"
)

type Key struct {
	Value     any
	Algorithm string
	KeyID     string
	Use       string
}

func (k Key) MarshalJSON() (b []byte, err error) {
	var jwk *JSONWebKey

	switch t := k.Value.(type) {
	case *rsa.PublicKey:
		jwk, err = rsaPublicKeyToJWK(t)
	case *rsa.PrivateKey:
		jwk, err = rsaPrivateKeyToJWK(t)
	case []byte:
		jwk, err = symmetricKeyToJWK(t)
	default:
		return nil, errors.New("unsupported key type")
	}

	if err != nil {
		return nil, err
	}

	jwk.Use = k.Use
	jwk.Algorithm = k.Algorithm
	jwk.KeyID = k.KeyID

	return json.Marshal(jwk)
}

func rsaPublicKeyToJWK(publicKey *rsa.PublicKey) (*JSONWebKey, error) {
	return &JSONWebKey{
		KeyType:        config.KeyTypeRSA,
		Modulus:        publicKey.N.Bytes(),
		PublicExponent: bigEndianFromInt(publicKey.E),
	}, nil
}

func rsaPrivateKeyToJWK(publicKey *rsa.PrivateKey) (*JSONWebKey, error) {
	return &JSONWebKey{
		KeyType:         config.KeyTypeRSA,
		Modulus:         publicKey.N.Bytes(),
		PublicExponent:  bigEndianFromInt(publicKey.E),
		PrivateExponent: publicKey.D.Bytes(),
		Prime0:          publicKey.Primes[0].Bytes(),
		Prime1:          publicKey.Primes[1].Bytes(),
		Dp:              publicKey.Precomputed.Dp.Bytes(),
		Dq:              publicKey.Precomputed.Dq.Bytes(),
		Qi:              publicKey.Precomputed.Qinv.Bytes(),
	}, nil
}

func symmetricKeyToJWK(key []byte) (*JSONWebKey, error) {
	return &JSONWebKey{
		KeyType:      config.KeyTypeSymmetric,
		SymmetricKey: key,
	}, nil
}

func bigEndianFromInt(i int) bigEndian {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(i))
	return bytes.TrimLeft(data, "\x00")
}

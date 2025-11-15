package key

import (
	"crypto/rsa"

	"github.com/tuanta7/keys/internal/config"
)

func rsaPublicKeyToJWK(publicKey *rsa.PublicKey) (*JSONWebKey, error) {
	return &JSONWebKey{
		KeyType:        config.KeyTypeRSA,
		Modulus:        NewBytes(publicKey.N.Bytes()),
		PublicExponent: NewBytes(IntToBigEndian(publicKey.E)),
	}, nil
}

func rsaPrivateKeyToJWK(publicKey *rsa.PrivateKey) (*JSONWebKey, error) {
	return &JSONWebKey{
		KeyType:         config.KeyTypeRSA,
		Modulus:         NewBytes(publicKey.N.Bytes()),
		PublicExponent:  NewBytes(IntToBigEndian(publicKey.E)),
		PrivateExponent: NewBytes(publicKey.D.Bytes()),
		Prime0:          NewBytes(publicKey.Primes[0].Bytes()),
		Prime1:          NewBytes(publicKey.Primes[1].Bytes()),
		Dp:              NewBytes(publicKey.Precomputed.Dp.Bytes()),
		Dq:              NewBytes(publicKey.Precomputed.Dq.Bytes()),
		Qi:              NewBytes(publicKey.Precomputed.Qinv.Bytes()),
	}, nil
}

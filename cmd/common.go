package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/tuanta7/keys/internal/config"
)

var (
	bits         int
	outputFormat string
	keyFile      string
)

type ParsedKey struct {
	Kind    string
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	PKCS1   []byte // raw PKCS#1 bytes
	JWK     []byte
}

func parseKey(data []byte) (*ParsedKey, error) {
	// Try PEM
	if block, _ := pem.Decode(data); block != nil {
		switch block.Type {
		case config.KeyTypeRSAPrivateKey:
			prv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
			}
			return &ParsedKey{
				Kind:    config.KeyTypeRSAPrivateKey,
				Private: prv,
				PKCS1:   x509.MarshalPKCS1PrivateKey(prv),
			}, nil
		case config.KeyTypeRSAPublicKey:
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#1 public key: %w", err)
			}
			return &ParsedKey{
				Kind:   config.KeyTypeRSAPublicKey,
				Public: pub,
				PKCS1:  x509.MarshalPKCS1PublicKey(pub),
			}, nil
		default:
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
	}

	// Assume DER
	if prv, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return &ParsedKey{
			Kind:    config.KeyTypeRSAPrivateKey,
			Private: prv,
			PKCS1:   x509.MarshalPKCS1PrivateKey(prv),
		}, nil
	}

	if pub, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return &ParsedKey{
			Kind:   config.KeyTypeRSAPublicKey,
			Public: pub,
			PKCS1:  x509.MarshalPKCS1PublicKey(pub),
		}, nil
	}

	return nil, errors.New("unrecognized key format (not PEM or PKCS#1 DER)")
}

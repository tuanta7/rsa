package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/tuanta7/keys/internal/config"
)

var (
	bits         int
	outputFormat string
	keyFile      string
)

func parseKey(contents []byte) (keyType string, keyBody []byte, err error) {
	block, _ := pem.Decode(contents)
	if block != nil {
		return block.Type, block.Bytes, nil
	}

	publicKey, _ := x509.ParsePKCS1PublicKey(contents)
	if publicKey != nil {
		return config.KeyTypeRSAPublicKey, contents, nil
	}

	privateKey, _ := x509.ParsePKCS1PrivateKey(contents)
	if privateKey != nil {
		return config.KeyTypeRSAPrivateKey, contents, nil
	}

	return "", nil, errors.New("unsupported key format")
}

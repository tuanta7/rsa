package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/tuanta7/rsa-tools/internal/config"
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
		return config.KeyTypePublicKey, contents, nil
	}

	privateKey, _ := x509.ParsePKCS1PrivateKey(contents)
	if privateKey != nil {
		return config.KeyTypePrivateKey, contents, nil
	}

	return "", nil, errors.New("unsupported key format")
}

func jwkEncode(r *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(r.Bytes())
}

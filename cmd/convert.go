package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tuanta7/keys/bigint"
	"github.com/tuanta7/keys/internal/config"
	"github.com/tuanta7/keys/internal/key"
)

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert RSA key in PEM or DER format to different formats",
	Long: `Convert an existing RSA key file to a different format.

Supported output formats:
- jwk: JSON Web Value format
- base64: Base64 encoded format (URL encoded, no padding)

The command will read the key file and output the converted format.

Example usage:
  rsa convert --key-file id_rsa --output-format jwk
  rsa convert --key-file id_rsa.pub --output-format base64
  rsa convert --key-file id_rsa.pub --output-format jwk > id_rsa.pub.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		contents, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		var converter KeyConverter
		switch strings.ToLower(outputFormat) {
		case "jwk":
			converter = JWKConverter{}
		case "base64":
			converter = Base64Converter{}
		default:
			return fmt.Errorf("unsupported output format: %s", outputFormat)
		}

		result, err := converter.Convert(contents)
		if err != nil {
			return err
		}

		fmt.Println(string(result))
		return nil
	},
}

type KeyConverter interface {
	Convert(data []byte) ([]byte, error)
}

type Base64Converter struct{}

func (c Base64Converter) Convert(data []byte) ([]byte, error) {
	base64Bytes := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(base64Bytes, data)
	return base64Bytes, nil
}

type JWKConverter struct{}

func (c JWKConverter) Convert(data []byte) ([]byte, error) {
	keyType, keyBody, err := parseKey(data)
	if err != nil {
		return nil, err
	}

	switch keyType {
	case config.KeyTypeRSAPrivateKey:
		return convertPrivateKeyToJWK(keyBody)
	case config.KeyTypeRSAPublicKey:
		return convertPublicKeyToJWK(keyBody)
	default:
		return nil, fmt.Errorf("unsupported block type: %s", keyType)
	}
}

func convertPublicKeyToJWK(keyBody []byte) ([]byte, error) {
	publicKey, err := x509.ParsePKCS1PublicKey(keyBody)
	if err != nil {
		return nil, err
	}

	jwk := &key.JSONWebKey{
		KeyType:        config.KeyTypeRSA,
		Modulus:        bigint.EncodeToString(publicKey.N),
		PublicExponent: bigint.EncodeToString(big.NewInt(int64(publicKey.E))),
	}

	return json.MarshalIndent(jwk, "", "\t")
}

func convertPrivateKeyToJWK(keyBody []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBody)
	if err != nil {
		return nil, err
	}

	jwk := &key.JSONWebKey{
		KeyType:         config.KeyTypeRSA,
		Modulus:         bigint.EncodeToString(privateKey.N),
		PublicExponent:  bigint.EncodeToString(big.NewInt(int64(privateKey.E))),
		PrivateExponent: bigint.EncodeToString(privateKey.D),
		Prime0:          bigint.EncodeToString(privateKey.Primes[0]),
		Prime1:          bigint.EncodeToString(privateKey.Primes[1]),
		Dp:              bigint.EncodeToString(privateKey.Precomputed.Dp),
		Dq:              bigint.EncodeToString(privateKey.Precomputed.Dq),
		Qi:              bigint.EncodeToString(privateKey.Precomputed.Qinv),
	}

	return json.MarshalIndent(jwk, "", "\t")
}

func init() {
	rootCmd.AddCommand(convertCmd)

	convertCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Value to convert")
	convertCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "", "Value format to convert to")
}

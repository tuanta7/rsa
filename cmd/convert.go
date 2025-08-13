package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gitlab.com/tuanta02/rsa-tools/internal/config"
	"gitlab.com/tuanta02/rsa-tools/internal/domain"
)

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert RSA key in PEM or DER format to different formats",
	Long: `Convert an existing RSA key file to a different format.

Supported output formats:
- jwk: JSON Web Key format
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
	case config.KeyTypePrivateKey:
		return convertPrivateKeyToJWK(keyBody)
	case config.KeyTypePublicKey:
		return convertPublicKeyToJWK(keyBody)
	default:
		return nil, fmt.Errorf("unsupported block type: %s", keyType)
	}
}

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

func convertPublicKeyToJWK(keyBody []byte) ([]byte, error) {
	publicKey, err := x509.ParsePKCS1PublicKey(keyBody)
	if err != nil {
		return nil, err
	}

	jwk := &domain.RSAPublicJWK{
		KeyType: config.KeyTypeRSA,
		N:       base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	return json.MarshalIndent(jwk, "", "\t")
}

func convertPrivateKeyToJWK(keyBody []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBody)
	if err != nil {
		return nil, err
	}

	jwk := &domain.RSAPrivateJWK{
		RSAPublicJWK: domain.RSAPublicJWK{
			KeyType: config.KeyTypeRSA,
			N:       base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
			E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		},
		D:    base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes()),
		P:    base64.RawURLEncoding.EncodeToString(privateKey.Primes[0].Bytes()),
		Q:    base64.RawURLEncoding.EncodeToString(privateKey.Primes[1].Bytes()),
		Dp:   base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dp.Bytes()),
		Dq:   base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dq.Bytes()),
		QInv: base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Qinv.Bytes()),
	}

	return json.MarshalIndent(jwk, "", "\t")
}

func init() {
	rootCmd.AddCommand(convertCmd)

	convertCmd.Flags().StringVar(&keyFile, "key-file", "", "Key to convert")
	convertCmd.Flags().StringVar(&outputFormat, "output-format", "", "Key format to convert to")
}

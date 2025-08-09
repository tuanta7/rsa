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
	"gitlab.com/tuanta02/rsa-tools/config"
)

var keyFile string

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert RSA key to different formats",
	Long: `Convert an existing RSA key file to a different format.

Supported output formats:
- jwk: JSON Web Key format
- base64: Base64 encoded format

The command will read the key file and output the converted format.

Example usage:
  rsa convert --key-file id_rsa --output-format jwk
  rsa convert --key-file id_rsa.pub --output-format base64`,
	RunE: func(cmd *cobra.Command, args []string) error {
		contents, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}

		switch strings.ToLower(outputFormat) {
		case "jwk":
			block, _ := pem.Decode(contents)
			if block == nil {
				return errors.New("no key found")
			}

			if block.Type == config.KeyTypePublicKey {
				return convertPrivateKeyPEMToJWK(block)
			}

		case "base64":
			base64Bytes := make([]byte, base64.StdEncoding.EncodedLen(len(contents)))
			base64.StdEncoding.Encode(base64Bytes, contents)
			fmt.Println(string(base64Bytes))
		default:
			return errors.New("unsupported format")
		}

		return nil
	},
}

func convertPrivateKeyPEMToJWK(block *pem.Block) error {
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	jwk := map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		"d":   base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes()),
		"p":   base64.RawURLEncoding.EncodeToString(privateKey.Primes[0].Bytes()),
		"q":   base64.RawURLEncoding.EncodeToString(privateKey.Primes[1].Bytes()),
	}

	jwkJSON, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(jwkJSON))
	return nil
}

func init() {
	rootCmd.AddCommand(convertCmd)

	convertCmd.Flags().StringVar(&keyFile, "key-file", "", "Key to convert")
	convertCmd.Flags().StringVar(&outputFormat, "output-format", "", "Key format to convert to")
}

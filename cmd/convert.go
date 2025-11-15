package cmd

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuanta7/keys/internal/config"
	"github.com/tuanta7/keys/internal/key"
)

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "Convert RSA key in PEM or DER format to different formats",
	Long: `Convert an existing RSA key file to another format.

Supported output formats:
\- jwk
\- pem
\- der

Example:
  rsa convert --key-file id_rsa --output-format jwk
  rsa convert --key-file id_rsa.pub --output-format pem
  rsa convert --key-file id_rsa.pub --output-format jwk > id_rsa.pub.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if keyFile == "" {
			return errors.New("missing --key-file")
		}

		if outputFormat == "" {
			outputFormat = "jwk"
		}

		data, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}

		parsed, err := parseKey(data)
		if err != nil {
			return fmt.Errorf("parse key: %w", err)
		}

		out, err := marshalKey(parsed, strings.ToLower(outputFormat))
		if err != nil {
			return fmt.Errorf("marshal key: %w", err)
		}

		fmt.Println(string(out))
		return nil
	},
}

func marshalKey(p *ParsedKey, format string) ([]byte, error) {
	switch format {
	case "der":
		return p.PKCS1, nil
	case "pem":
		return marshalPEM(p), nil
	case "jwk":
		return marshalJWK(p)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

func marshalPEM(p *ParsedKey) []byte {
	var block *pem.Block
	if p.Kind == config.KeyTypeRSAPrivateKey {
		block = &pem.Block{Type: config.KeyTypeRSAPrivateKey, Bytes: p.PKCS1}
	} else {
		block = &pem.Block{Type: config.KeyTypeRSAPublicKey, Bytes: p.PKCS1}
	}
	return pem.EncodeToMemory(block)
}

func marshalJWK(p *ParsedKey) ([]byte, error) {
	if p.Kind == config.KeyTypeRSAPrivateKey {
		return json.MarshalIndent(key.Key{Value: p.Private}, "", "\t")
	}
	return json.MarshalIndent(key.Key{Value: p.Public}, "", "\t")
}

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Key file to convert")
	convertCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "", "Target format: pem, der, jwk")
}

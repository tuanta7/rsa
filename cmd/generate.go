package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tuanta7/keys/internal/config"
	"github.com/tuanta7/keys/internal/key"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate RSA key pair",
	Long: `Generate a new RSA key pair (private and public keys) and save them to the specified directory.

The command creates two files in the output directory:
- id_rsa: The private key file
- id_rsa.pub: The public key file

You can customize the key size with --bits flag and the output format with --output-format flag.

Example usage:
  rsa generate /path/to/keys
  rsa generate . --bits=4096
  rsa generate /home/user/.ssh --output-format=der`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing output directory path")
		}

		if len(args) > 1 {
			return fmt.Errorf("too many arguments provided (received %d, expected 1)", len(args))
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDirectory := args[0]

		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			fmt.Printf("Error generating RSA key: %v\n", err)
			return err
		}

		err = writePrivateKey(privateKey, outputDirectory)
		if err != nil {
			return err
		}

		err = writePublicKey(&privateKey.PublicKey, outputDirectory)
		if err != nil {
			return err
		}

		return nil
	},
}

func writePublicKey(publicKey *rsa.PublicKey, outputDirectory string) error {
	publicKeyFilePath := filepath.Join(outputDirectory, "id_rsa.pub")

	file, err := os.Create(publicKeyFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	switch strings.ToUpper(outputFormat) {
	case config.KeyFormatDER:
		publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
		_, err = file.Write(publicKeyBytes)
	case config.KeyFormatPEM:
		publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
		publicKeyPEM := &pem.Block{
			Type:  config.KeyTypeRSAPublicKey,
			Bytes: publicKeyBytes,
		}
		err = pem.Encode(file, publicKeyPEM)
	case config.KeyFormatJWK:
		k := key.Key{
			Value: publicKey,
		}

		keyJSON, marshalErr := json.MarshalIndent(k, "", "\t")
		if marshalErr != nil {
			return marshalErr
		}

		_, err = file.Write(keyJSON)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	return err
}

func writePrivateKey(privateKey *rsa.PrivateKey, outputDirectory string) error {
	privateKeyFilePath := filepath.Join(outputDirectory, "id_rsa")

	file, err := os.Create(privateKeyFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	switch strings.ToUpper(outputFormat) {
	case config.KeyFormatDER:
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		_, err = file.Write(privateKeyBytes)
	case config.KeyFormatPEM:
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := &pem.Block{
			Type:  config.KeyTypeRSAPrivateKey,
			Bytes: privateKeyBytes,
		}
		err = pem.Encode(file, privateKeyPEM)
	case config.KeyFormatJWK:
		k := key.Key{
			Value: privateKey,
		}

		keyJSON, marshalErr := json.MarshalIndent(k, "", "\t")
		if marshalErr != nil {
			return marshalErr
		}

		_, err = file.Write(keyJSON)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	return err
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().IntVarP(&bits, "bits", "b", 2048, "RSA key size (e.g., 2048, 4096)")
	generateCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "pem", "Output format: pem, der, jwk")
}

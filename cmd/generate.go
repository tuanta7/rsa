package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gitlab.com/tuanta02/rsa-tools/config"
)

var bits int
var outputFormat string

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

	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPEM := &pem.Block{
		Type:  config.KeyTypePublicKey,
		Bytes: publicKeyBytes,
	}

	err = write(file, publicKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func writePrivateKey(privateKey *rsa.PrivateKey, outputDirectory string) error {
	privateKeyFilePath := filepath.Join(outputDirectory, "id_rsa")

	file, err := os.Create(privateKeyFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  config.KeyTypePrivateKey,
		Bytes: privateKeyBytes,
	}

	err = write(file, privateKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func write(file *os.File, pemBlock *pem.Block) (err error) {
	switch strings.ToUpper(outputFormat) {
	case config.KeyFormatDER:
		_, err = file.Write(pemBlock.Bytes)
	case config.KeyFormatPEM:
		err = pem.Encode(file, pemBlock)
	case config.KeyFormatJWK:
		fallthrough
	default:
		return errors.New("unsupported output format")
	}

	return err
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().IntVarP(&bits, "bits", "b", 2048, "RSA key size (e.g., 2048, 4096)")
	generateCmd.Flags().StringVar(&outputFormat, "output-format", "pem", "Output format (pem, der)")
}

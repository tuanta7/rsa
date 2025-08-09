package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var bits int
var outputFormat string

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "A brief description of your command",
	Long:  ``,
	Args:  cobra.ExactArgs(1),
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
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyFilePath := filepath.Join(outputDirectory, "id_rsa.pub")

	file, err := os.Create(publicKeyFilePath)
	if err != nil {
		return err
	}

	err = pem.Encode(file, publicKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func writePrivateKey(privateKey *rsa.PrivateKey, outputDirectory string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFilePath := filepath.Join(outputDirectory, "id_rsa")

	file, err := os.Create(privateKeyFilePath)
	if err != nil {
		return err
	}

	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().IntVarP(&bits, "bits", "b", 2048, "RSA key size (e.g., 2048, 4096)")
	generateCmd.Flags().StringVar(&outputFormat, "format", "pem", "Output format (e.g., pem, der)")
}

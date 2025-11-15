package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tuanta7/keys/internal/generator"
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
  rsa generate --bits=4096 . 
  rsa generate --output-format=der /home/user/.ssh`,
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
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}

		generator := &generator.RSAKeyGenerator{
			OutputDir: outputDirectory,
			Format:    strings.ToUpper(outputFormat),
		}

		if err := generator.WriteKeyPair(privateKey); err != nil {
			return fmt.Errorf("failed to write key pair: %w", err)
		}

		fmt.Printf("Successfully generated RSA key pair in %s\n", outputDirectory)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().IntVarP(&bits, "bits", "b", 2048, "RSA key size (e.g., 2048, 4096)")
	generateCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "pem", "Output format: pem, der, jwk")
}

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rsa-tools",
	Short: "A CLI tool for RSA key management, encryption, decryption, signing, and verification.",
	Long: `rsa-tools is a command-line utility for working with RSA cryptography. 
It provides commands to generate, inspect, convert, encrypt, decrypt, sign, and verify RSA keys and data.

Features:
- Generate RSA key pairs
- Inspect and convert key formats (PEM, JWK, etc.)
- Encrypt and decrypt files or messages
- Sign and verify data

Examples:
  rsa-tools generate --bits 2048 .
  rsa-tools encrypt --in plaintext.txt --out ciphertext.bin
  rsa-tools sign --key private.pem --in data.txt --out signature.bin

Use "rsa-tools [command] --help" for more information about a command.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

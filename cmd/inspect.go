package cmd

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tuanta7/rsa-tools/internal/config"
)

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect and display RSA key information",
	Long: `Analyze RSA key files and display detailed information about the key.
	
This command supports various RSA key formats including:
- PEM encoded PKCS#1 keys
- DER formatted keys
- JWK (JSON Web Key) format

For public keys, it displays:
- Key type and size
- Public exponent
- Modulus

For private keys, it additionally displays:
- Prime factors (p and q)
- CRT (Chinese Remainder Theorem) values
- Additional private key parameters

Example:
  rsa-tools inspect private.pem
  rsa-tools inspect public_key.der`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing key file path")
		}

		if len(args) > 1 {
			return fmt.Errorf("too many arguments provided (received %d, expected 1)", len(args))
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		keyFilePath := args[0]

		contents, err := os.ReadFile(keyFilePath)
		if err != nil {
			return err
		}

		keyType, keyBody, err := parseKey(contents)

		switch keyType {
		case config.KeyTypePrivateKey:
			return inspectPrivateKey(keyBody)
		case config.KeyTypePublicKey:
			return inspectPublicKey(keyBody)
		default:
			return fmt.Errorf("unsupported block type: %s", keyType)
		}
	},
}

func inspectPublicKey(keyBody []byte) error {
	publicKey, err := x509.ParsePKCS1PublicKey(keyBody)
	if err != nil {
		return err
	}

	fmt.Printf("Key Type: %s\n", config.KeyTypePublicKey)
	fmt.Printf("Key Size: %d bits\n", publicKey.Size()*8)
	fmt.Printf("Public Exponent (e): %d\n", publicKey.E)
	fmt.Printf("Modulus (n): %s\n", publicKey.N)

	return nil
}

func inspectPrivateKey(keyBody []byte) error {
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBody)
	if err != nil {
		return err
	}

	fmt.Printf("Key Type: %s\n", config.KeyTypePrivateKey)
	fmt.Printf("Key Size: %d bits (%d bytes)\n", privateKey.Size()*8, privateKey.Size())
	fmt.Printf("Public Exponent (e): %d\n", privateKey.E)
	fmt.Printf("Private Exponent (d): %d\n", privateKey.D)
	fmt.Printf("Modulus (n): %s (%d bits)\n", privateKey.N, privateKey.N.BitLen())
	fmt.Println("")
	fmt.Printf("Primes: p x q = n\n")
	fmt.Printf("p (%d bits): %s\n", privateKey.Primes[0].BitLen(), privateKey.Primes[0])
	fmt.Printf("n (%d bits): %s\n", privateKey.Primes[1].BitLen(), privateKey.Primes[1])
	fmt.Println("")
	fmt.Printf("CRT Values\n")
	fmt.Printf("dp = d mod (p-1): %s\n", privateKey.Precomputed.Dp)
	fmt.Printf("dq = d mod (q-1): %s\n", privateKey.Precomputed.Dq)
	fmt.Printf("qi = q ^ -1 mod p: %s\n", privateKey.Precomputed.Qinv)

	return nil
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

package cmd

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/tuanta02/rsa-tools/internal/config"
)

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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
	fmt.Printf("Public Exponent: %d\n", publicKey.E)
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
	fmt.Printf("Public Exponent: %d\n", privateKey.E)
	fmt.Printf("Modulus (n): %s (%d bits)\n", privateKey.N, privateKey.N.BitLen())
	fmt.Println("")
	fmt.Printf("Primes: p x q = n\n")
	fmt.Printf("p (%d bits): %s\n", privateKey.Primes[0].BitLen(), privateKey.Primes[0])
	fmt.Printf("n (%d bits): %s\n", privateKey.Primes[1].BitLen(), privateKey.Primes[1])
	fmt.Println("")
	fmt.Printf("CRT Values\n")
	fmt.Printf("dp = d mod (p-1): %s", privateKey.Precomputed.Dp)
	fmt.Printf("dq = d mod (q-1): %s", privateKey.Precomputed.Dq)
	fmt.Printf("qi = q ^ -1 mod p: %s", privateKey.Precomputed.Qinv)

	return nil
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

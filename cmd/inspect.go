package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("inspect called")
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
	inspectCmd.Flags().StringVar(&keyFile, "key-file", "", "Key to inspect")
}

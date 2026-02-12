package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("trustwatch", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

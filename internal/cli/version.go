package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("trustwatch %s (commit: %s, built: %s, go: %s)\n",
			version, commit, date, runtime.Version())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

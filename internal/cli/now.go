package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var nowCmd = &cobra.Command{
	Use:   "now",
	Short: "Show trust surface problems right now",
	Long: `Discover and probe all trust surfaces, display problems in a TUI.

Exit codes:
  0  No problems found
  1  Warnings exist (certs expiring within warn threshold)
  2  Critical problems (certs expiring within crit threshold or expired)
  3  Discovery or probe errors`,
	RunE: runNow,
}

func init() {
	rootCmd.AddCommand(nowCmd)
	nowCmd.Flags().String("config", "", "Path to config file")
	nowCmd.Flags().String("kubeconfig", "", "Path to kubeconfig")
	nowCmd.Flags().String("context", "", "Kubernetes context to use")
	nowCmd.Flags().StringSlice("namespace", nil, "Namespaces to scan (empty = all)")
	nowCmd.Flags().Duration("warn-before", 0, "Warn threshold (default from config)")
	nowCmd.Flags().Duration("crit-before", 0, "Critical threshold (default from config)")
}

func runNow(_ *cobra.Command, _ []string) error {
	fmt.Println("trustwatch", version)
	fmt.Println("Discovery and probing not yet implemented.")
	return nil
}

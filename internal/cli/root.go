package cli

import (
	"github.com/spf13/cobra"
)

var version = "dev"

// SetVersion sets the version string (called from main).
func SetVersion(v string) {
	version = v
}

var rootCmd = &cobra.Command{
	Use:   "trustwatch",
	Short: "Kubernetes trust surface monitoring",
	Long: `trustwatch discovers and monitors TLS trust surfaces in Kubernetes clusters.

It finds expiring certificates on admission webhooks, API aggregation endpoints,
service mesh issuers, annotated services, and external dependencies — then reports
only the ones that matter.`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as in-cluster service with web UI and /metrics",
	Long: `Start trustwatch as a long-running service inside a Kubernetes cluster.

Exposes:
  /         Problems web UI (only expiring/failed trust surfaces)
  /metrics  Prometheus scrape endpoint
  /healthz  Liveness probe
  /api/v1/snapshot  JSON snapshot of all findings`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String("config", "/etc/trustwatch/config.yaml", "Path to config file")
	serveCmd.Flags().String("listen", ":8080", "Listen address")
}

func runServe(_ *cobra.Command, _ []string) error {
	fmt.Println("trustwatch serve", version)
	fmt.Println("Server not yet implemented.")
	return nil
}

// Package cli provides the trustwatch CLI commands.
package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"
var commit = "none"
var date = "unknown"

// SetBuildInfo sets the version info (called from main).
func SetBuildInfo(v, c, d string) {
	version = v
	commit = c
	date = d
}

var rootCmd = &cobra.Command{
	Use:   "trustwatch",
	Short: "Kubernetes trust surface monitoring",
	Long: `trustwatch discovers and monitors TLS trust surfaces in Kubernetes clusters.

It finds expiring certificates on admission webhooks, API aggregation endpoints,
service mesh issuers, annotated services, and external dependencies — then reports
only the ones that matter.`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return setupLogging(cmd)
	},
}

func init() {
	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "text", "Log format (text, json)")
	rootCmd.PersistentFlags().String("otel-endpoint", "", "OTLP gRPC endpoint for tracing (e.g. localhost:4317)")
}

func setupLogging(cmd *cobra.Command) error {
	levelStr, _ := cmd.Flags().GetString("log-level")   //nolint:errcheck // flag registered above
	formatStr, _ := cmd.Flags().GetString("log-format") //nolint:errcheck // flag registered above

	var level slog.Level
	switch levelStr {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch formatStr {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
	return nil
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/trustwatch/internal/config"
)

var validateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a trustwatch config file",
	Long: `Load and validate a trustwatch YAML config file without connecting to a cluster.

Checks for YAML syntax errors, invalid thresholds, and missing required fields.
Exits 0 on success, 1 on validation failure.`,
	Example: `  trustwatch validate /etc/trustwatch/config.yaml
  trustwatch validate config.yaml && echo "Config OK"`,
	Args: cobra.ExactArgs(1),
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	_, err := config.Load(args[0])
	if err != nil {
		cmd.PrintErrln(err)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		return fmt.Errorf("validation failed")
	}
	cmd.Println("config OK")
	return nil
}

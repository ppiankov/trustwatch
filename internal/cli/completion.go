package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for trustwatch.

To load completions:

Bash:
  $ source <(trustwatch completion bash)
  # Or persist across sessions:
  $ trustwatch completion bash > /etc/bash_completion.d/trustwatch

Zsh:
  $ source <(trustwatch completion zsh)
  # Or persist:
  $ trustwatch completion zsh > "${fpath[1]}/_trustwatch"

Fish:
  $ trustwatch completion fish | source
  # Or persist:
  $ trustwatch completion fish > ~/.config/fish/completions/trustwatch.fish

PowerShell:
  PS> trustwatch completion powershell | Out-String | Invoke-Expression`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

package cli

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ppiankov/trustwatch/internal/socks5"
)

var socks5Cmd = &cobra.Command{
	Use:    "socks5",
	Short:  "Run embedded SOCKS5 proxy (used by --tunnel)",
	Hidden: true,
	RunE:   runSocks5,
}

func init() {
	rootCmd.AddCommand(socks5Cmd)
}

func runSocks5(_ *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s := &socks5.Server{Addr: ":1080"}
	return s.ListenAndServe(ctx)
}

package main

import (
	"fmt"
	"os"

	"github.com/ppiankov/trustwatch/internal/cli"
)

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	cli.SetVersion(Version)
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Package main is the trustwatch CLI entry point.
package main

import (
	"fmt"
	"os"

	"github.com/ppiankov/trustwatch/internal/cli"
)

// Build info set at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetBuildInfo(version, commit, date)
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

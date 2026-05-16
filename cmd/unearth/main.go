// Command unearth is the CLI entrypoint. main is intentionally tiny: it
// builds the root cobra command and runs it, and lets a non-zero exit code
// from the command tree propagate. Every interesting behavior lives in the
// internal/cli package so it can be driven from tests without forking a
// real process.
package main

import (
	"os"

	"github.com/unearth-tool/unearth/cmd/unearth/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

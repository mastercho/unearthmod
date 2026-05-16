// Command unearth is the CLI for origin-IP discovery.
//
// The full CLI -- flags, input modes and output formats -- is implemented in
// Packet 4. This stub keeps the build honest until then.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "unearth: CLI not yet implemented -- see Packet 4")
	os.Exit(1)
}

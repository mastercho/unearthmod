// Package cli builds the cobra command tree for the unearth binary.
//
// Run is the only exported entrypoint; main.go calls it and propagates the
// exit code. Tests call Run with synthetic argv and captured I/O streams.
package cli

import (
	"context"
	"io"
	"os/signal"
	"syscall"
)

// Exit codes follow the scheme stated in Packet 4 §C.7:
//
//	0 — ran successfully (no candidates found is still success).
//	1 — usage error (bad flags, no input, malformed file).
//	2 — execution error (every target failed to run).
const (
	exitOK         = 0
	exitUsageError = 1
	exitExecError  = 2
)

// Run constructs the cobra root command and executes it with args. It
// returns the process exit code. The supplied streams replace stdin/stdout/
// stderr for the lifetime of the call; tests pass bytes.Buffer.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Cancel the global context on SIGINT/SIGTERM so in-flight discoveries
	// unwind cleanly rather than dying mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := newRootCmd(stdin, stdout, stderr)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SilenceUsage = true  // we print usage ourselves on flag errors
	root.SilenceErrors = true // we print errors ourselves so we control exit codes

	if err := root.ExecuteContext(ctx); err != nil {
		// usageError carries an exit code; everything else is exec error.
		if ue, ok := err.(*usageError); ok {
			_, _ = io.WriteString(stderr, "unearth: "+ue.msg+"\n")
			return ue.code
		}
		_, _ = io.WriteString(stderr, "unearth: "+err.Error()+"\n")
		return exitExecError
	}
	return exitOK
}

// usageError is the error type Run unwraps to a non-default exit code.
type usageError struct {
	msg  string
	code int
}

func (e *usageError) Error() string { return e.msg }

func errUsage(msg string) error { return &usageError{msg: msg, code: exitUsageError} }

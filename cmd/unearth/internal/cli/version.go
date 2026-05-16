package cli

import (
	"fmt"
	"io"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/unearth-tool/unearth/internal/httpclient"
)

func newVersionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		RunE: func(_ *cobra.Command, _ []string) error {
			printVersion(stdout)
			return nil
		},
	}
}

func printVersion(w io.Writer) {
	commit, buildDate := vcsInfo()
	_, _ = fmt.Fprintf(w, "unearth %s\n", httpclient.Version)
	if commit != "" {
		_, _ = fmt.Fprintf(w, "commit:  %s\n", commit)
	}
	if buildDate != "" {
		_, _ = fmt.Fprintf(w, "built:   %s\n", buildDate)
	}
}

// vcsInfo pulls the VCS commit and build time out of the binary's
// embedded build info, when available. `go build` populates these fields
// when the source is under version control and modules are enabled.
func vcsInfo() (commit, buildDate string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.time":
			buildDate = s.Value
		}
	}
	return commit, buildDate
}

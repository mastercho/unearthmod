package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unearth-tool/unearth/pkg/cache"
)

func newCacheCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "cache",
		Short: "Manage the on-disk result cache",
	}
	root.AddCommand(newCacheStatsCmd(stdout))
	root.AddCommand(newCachePurgeCmd(stdout))
	root.AddCommand(newCacheClearCmd(stdin, stdout, stderr))
	return root
}

func newCacheStatsCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show cache row counts and the on-disk path",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := cache.Open("")
			if err != nil {
				return fmt.Errorf("opening cache: %w", err)
			}
			defer func() { _ = c.Close() }()
			total, expired, err := c.Stats()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "path:    %s\ntotal:   %d\nexpired: %d\nlive:    %d\n",
				c.Path(), total, expired, total-expired)
			return nil
		},
	}
}

func newCachePurgeCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "purge",
		Short: "Delete all expired cache entries",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := cache.Open("")
			if err != nil {
				return fmt.Errorf("opening cache: %w", err)
			}
			defer func() { _ = c.Close() }()
			n, err := c.Purge()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "purged %d expired entries\n", n)
			return nil
		},
	}
}

func newCacheClearCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Remove the cache file entirely (requires confirmation)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := cache.Open("")
			if err != nil {
				return fmt.Errorf("opening cache: %w", err)
			}
			path := c.Path()
			_ = c.Close()
			if !yes {
				_, _ = fmt.Fprintf(stderr, "About to delete %s. Type 'yes' to confirm: ", path)
				answer, _ := bufio.NewReader(stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
					return errUsage("cache clear cancelled")
				}
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			// Also remove SQLite sidecar files (-wal, -shm) when present.
			for _, suffix := range []string{"-wal", "-shm"} {
				_ = os.Remove(path + suffix)
			}
			_, _ = fmt.Fprintf(stdout, "removed %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the confirmation prompt")
	return cmd
}

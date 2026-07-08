package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/unearth-tool/unearth/pkg/unearth"
)

// sink is the output strategy. Three implementations: jsonl (stream per
// candidate), json (one big array at the end), table (human-readable per
// target). All three honor the --top cap.
type sink interface {
	// write emits whatever the format prints per result. For streaming
	// formats (jsonl, table) that's per-target; for accumulating formats
	// (json) it just buffers.
	write(stdout, stderr io.Writer, res *unearth.Result, f *rootFlags) error
	// flush is called once after every target has been processed; the
	// json sink uses it to emit the full array, the others no-op.
	flush(stdout io.Writer, all []*unearth.Result) error
}

func newSink(format string, useColor bool, top int) (sink, error) {
	switch format {
	case "jsonl":
		return &jsonlSink{top: top}, nil
	case "json":
		return &jsonSink{top: top}, nil
	case "table":
		return &tableSink{top: top, color: useColor}, nil
	default:
		return nil, errUsage("invalid --output: " + format)
	}
}

// --- jsonl -----------------------------------------------------------

type jsonlSink struct{ top int }

// jsonlRow is one line of JSONL: an augmented ScoredIP carrying the
// target it belongs to.
type jsonlRow struct {
	Target string `json:"target"`
	unearth.ScoredIP
}

func (s *jsonlSink) write(stdout, stderr io.Writer, res *unearth.Result, f *rootFlags) error {
	enc := json.NewEncoder(stdout)
	limit := capN(s.top, len(res.Candidates))
	for _, c := range res.Candidates[:limit] {
		if err := enc.Encode(jsonlRow{Target: res.Target, ScoredIP: c}); err != nil {
			return err
		}
	}
	// Per §C.6, Result-level info (CDN, errors, warnings) goes to stderr
	// under --verbose, never into the stdout JSONL stream.
	if f.verbose {
		emitResultMeta(stderr, res)
	}
	return nil
}

func (*jsonlSink) flush(io.Writer, []*unearth.Result) error { return nil }

// --- json ------------------------------------------------------------

type jsonSink struct{ top int }

func (*jsonSink) write(io.Writer, io.Writer, *unearth.Result, *rootFlags) error { return nil }

func (s *jsonSink) flush(stdout io.Writer, all []*unearth.Result) error {
	capped := make([]*unearth.Result, len(all))
	for i, r := range all {
		// Make a shallow copy so we can truncate Candidates without
		// mutating the caller's slice.
		cp := *r
		n := capN(s.top, len(cp.Candidates))
		cp.Candidates = cp.Candidates[:n]
		capped[i] = &cp
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(capped)
}

// --- table -----------------------------------------------------------

type tableSink struct {
	top   int
	color bool
}

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

func (s *tableSink) write(stdout, _ io.Writer, res *unearth.Result, _ *rootFlags) error {
	header := fmt.Sprintf("Target: %s", res.Target)
	if res.CDNDetected != "" {
		header += fmt.Sprintf("  (CDN: %s)", res.CDNDetected)
	}
	if _, err := fmt.Fprintln(stdout, header); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "  IP\tSCORE\tCORROB\tVALIDATION\tTECHNIQUES"); err != nil {
		return err
	}
	limit := capN(s.top, len(res.Candidates))
	for _, c := range res.Candidates[:limit] {
		score := fmt.Sprintf("%.3f", c.Score)
		if s.color {
			score = s.colorScore(c.Score) + score + ansiReset
		}
		names := make([]string, len(c.Techniques))
		for i, h := range c.Techniques {
			names[i] = h.Name
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%s\n",
			c.IP, score, c.Corroboration, validationLabel(c.Validation), strings.Join(names, ",")); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(res.Errors) > 0 || len(res.Warnings) > 0 {
		if _, err := fmt.Fprintln(stdout, ""); err != nil {
			return err
		}
		for _, e := range res.Errors {
			if _, err := fmt.Fprintf(stdout, "  ! %s: %s\n", e.Technique, e.Err); err != nil {
				return err
			}
		}
		for _, w := range res.Warnings {
			if _, err := fmt.Fprintf(stdout, "  ~ %s\n", w); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(stdout, "")
	return err
}

func (*tableSink) flush(io.Writer, []*unearth.Result) error { return nil }

func (s *tableSink) colorScore(score float64) string {
	switch {
	case score >= 0.8:
		return ansiGreen
	case score >= 0.5:
		return ansiYellow
	default:
		return ansiRed
	}
}

// --- helpers ---------------------------------------------------------

func capN(top, have int) int {
	if top <= 0 || top >= have {
		return have
	}
	return top
}

func emitResultMeta(w io.Writer, res *unearth.Result) {
	if res.CDNDetected != "" {
		_, _ = fmt.Fprintf(w, "unearth: %s — CDN: %s\n", res.Target, res.CDNDetected)
	}
	for _, r := range res.TechniqueRuns {
		if r.Reason != "" {
			_, _ = fmt.Fprintf(w, "unearth: %s — run[%s] status=%q candidates=%d reason=%q\n",
				res.Target, r.Technique, r.Status, r.Candidates, r.Reason)
			continue
		}
		_, _ = fmt.Fprintf(w, "unearth: %s — run[%s] status=%q candidates=%d\n",
			res.Target, r.Technique, r.Status, r.Candidates)
	}
	for _, c := range res.Candidates {
		if c.Validation == nil {
			continue
		}
		_, _ = fmt.Fprintf(w, "unearth: %s — confirmed[%s] via %s score=%.3f\n",
			res.Target, c.IP, c.Validation.Technique, c.Validation.Score)
	}
	for _, e := range res.Errors {
		_, _ = fmt.Fprintf(w, "unearth: %s — err[%s] reason=%q: %s\n",
			res.Target, e.Technique, e.Reason, e.Err)
	}
	for _, ww := range res.Warnings {
		_, _ = fmt.Fprintf(w, "unearth: %s — warn: %s\n", res.Target, ww)
	}
}

func validationLabel(v *unearth.Validation) string {
	if v == nil {
		return "candidate"
	}
	if v.Score > 0 {
		return fmt.Sprintf("%s %.2f", v.Status, v.Score)
	}
	return v.Status
}
